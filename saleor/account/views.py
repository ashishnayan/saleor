from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import views as django_views, get_user_model
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.translation import pgettext, ugettext_lazy as _
from django.views.decorators.http import require_POST

from ..checkout.utils import find_and_assign_anonymous_cart
from ..core.utils import get_paginator_items
from .emails import send_account_delete_confirmation_email, send_email_verification_link
from .forms import (
    ChangePasswordForm, LoginForm, PasswordResetForm, SignupForm,
    get_address_form, logout_on_password_change)
from .models import EmailVerification


@find_and_assign_anonymous_cart()
def login(request):
    kwargs = {
        'template_name': 'account/login.html',
        'authentication_form': LoginForm}
    return django_views.LoginView.as_view(**kwargs)(request, **kwargs)


@login_required
def logout(request):
    auth.logout(request)
    messages.success(request, _('You have been successfully logged out.'))
    return redirect(settings.LOGIN_REDIRECT_URL)


def signup(request):
    user = None
    if request.method == "POST":
        email = request.POST.get("email")
        if email:
            user = get_user_model().objects.filter(email=email, is_active=False).last()
    form = SignupForm(request.POST or None, instance=user)
    if form.is_valid():
        user = form.save()
        if settings.EMAIL_VERIFICATION_REQUIRED:
            messages.success(request, _('User has been created. Check your e-mail to verify your e-mail address.'))
            redirect_url = reverse_lazy("account:login")
            obj = EmailVerification.objects.create(user=user)
            send_email_verification_link(obj.token, user.email)
        else:
            password = form.cleaned_data.get('password')
            email = form.cleaned_data.get('email')
            user = auth.authenticate(
                request=request, email=email, password=password)
            if user:
                auth.login(request, user)
            messages.success(request, _('User has been created'))
            redirect_url = request.POST.get('next', settings.LOGIN_REDIRECT_URL)
        return redirect(redirect_url)
    ctx = {'form': form}
    return TemplateResponse(request, 'account/signup.html', ctx)


def email_verification(request, token):
    obj = get_object_or_404(EmailVerification, token=token)
    if timezone.now() - obj.created_on <= settings.EMAIL_VERIFICATION_LINK_EXPIRYTIME:
        obj.user.is_active = True
        obj.user.save()
        redirect_url = reverse_lazy("account:login")
    else:
        messages.error(request, _('Token Expired.'))
        redirect_url = reverse_lazy("account:signup")
    return redirect(redirect_url)


def password_reset(request):
    kwargs = {
        'template_name': 'account/password_reset.html',
        'success_url': reverse_lazy('account:reset-password-done'),
        'form_class': PasswordResetForm}
    return django_views.PasswordResetView.as_view(**kwargs)(request, **kwargs)


class PasswordResetConfirm(django_views.PasswordResetConfirmView):
    template_name = 'account/password_reset_from_key.html'
    success_url = reverse_lazy('account:reset-password-complete')
    token = None
    uidb64 = None


def password_reset_confirm(request, uidb64=None, token=None):
    kwargs = {
        'template_name': 'account/password_reset_from_key.html',
        'success_url': reverse_lazy('account:reset-password-complete'),
        'token': token,
        'uidb64': uidb64}
    return PasswordResetConfirm.as_view(**kwargs)(request, **kwargs)


@login_required
def details(request):
    password_form = get_or_process_password_form(request)
    orders = request.user.orders.confirmed().prefetch_related('lines')
    orders_paginated = get_paginator_items(
        orders, settings.PAGINATE_BY, request.GET.get('page'))
    ctx = {'addresses': request.user.addresses.all(),
           'orders': orders_paginated,
           'change_password_form': password_form}

    return TemplateResponse(request, 'account/details.html', ctx)


def get_or_process_password_form(request):
    form = ChangePasswordForm(data=request.POST or None, user=request.user)
    if form.is_valid():
        form.save()
        logout_on_password_change(request, form.user)
        messages.success(request, pgettext(
            'Storefront message', 'Password successfully changed.'))
    return form


@login_required
def address_edit(request, pk):
    address = get_object_or_404(request.user.addresses, pk=pk)
    address_form, preview = get_address_form(
        request.POST or None, instance=address,
        country_code=address.country.code)
    if address_form.is_valid() and not preview:
        address_form.save()
        message = pgettext(
            'Storefront message', 'Address successfully updated.')
        messages.success(request, message)
        return HttpResponseRedirect(reverse('account:details') + '#addresses')
    return TemplateResponse(
        request, 'account/address_edit.html',
        {'address_form': address_form})


@login_required
def address_delete(request, pk):
    address = get_object_or_404(request.user.addresses, pk=pk)
    if request.method == 'POST':
        address.delete()
        messages.success(
            request,
            pgettext('Storefront message', 'Address successfully removed'))
        return HttpResponseRedirect(reverse('account:details') + '#addresses')
    return TemplateResponse(
        request, 'account/address_delete.html', {'address': address})


@login_required
@require_POST
def account_delete(request):
    user = request.user
    send_account_delete_confirmation_email.delay(str(user.token), user.email)
    messages.success(
        request, pgettext(
            'Storefront message, when user requested his account removed',
            'Please check your inbox for a confirmation e-mail.'))
    return HttpResponseRedirect(reverse('account:details') + '#settings')


@login_required
def account_delete_confirm(request, token):
    user = request.user

    if str(request.user.token) != token:
        raise Http404('No such page!')

    if request.method == 'POST':
        user.delete()
        msg = pgettext(
            'Account deleted',
            'Your account was deleted successfully. '
            'In case of any trouble or questions feel free to contact us.')
        messages.success(request, msg)
        return redirect('home')

    return TemplateResponse(
        request, 'account/account_delete_prompt.html')
