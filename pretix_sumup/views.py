from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.template.response import TemplateResponse
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from pretix.base.middleware import _render_csp, get_language_from_request
from pretix.base.models import OrderPayment

from pretix_sumup.payment import SumUp


@csrf_exempt
@require_POST
def checkout_event(request, *args, **kwargs):
    provider = SumUp(request.event)
    order_payment = get_object_or_404(
        OrderPayment, pk=kwargs.get("payment"), order__event=request.event
    )
    provider._synchronize_payment_status(order_payment)
    return HttpResponse(status=204)


def payment_widget(request, *args, **kwargs):
    provider = SumUp(request.event)
    order_payment = get_object_or_404(
        OrderPayment,
        pk=kwargs.get("payment"),
        order__event=request.event,
        order__code=kwargs.get("order"),
        order__secret=kwargs.get("secret"),
    )
    # Synchronize the payment status as backup if the return webhook fails
    provider._synchronize_payment_status(order_payment)
    checkout_id = order_payment.info_data.get("sumup_checkout_id")
    if not checkout_id:
        raise ValidationError(_("No SumUp checkout ID found."))

    csp_nonce = get_random_string(10)
    
    csp = {
        "default-src": ["'self'", "*.sumup.com", "*.google.com"],
        "script-src": [
            f"'nonce-{csp_nonce}'", 
            "'self'", 
            "*.sumup.com", 
            "*.google.com",
            "'unsafe-inline'",  # Allow inline scripts
        ],
        "style-src": [
            "'self'",
            f"'nonce-{csp_nonce}'", 
            "'unsafe-inline'",  # Allow inline styles
            "*.sumup.com", 
            "*.google.com",
            "fonts.googleapis.com",  # Allow Google Fonts stylesheets
        ],
        "img-src": [
            "'self'",
            "*.google.com",
            "*.sumup.com",
            "*.gstatic.com",  # Google's image CDN
            "data:",  # Allow inline images
        ],
        "font-src": [
            "'self'", 
            "fonts.gstatic.com",  # Allow Google Fonts
        ],
        "frame-src": [
            "*.sumup.com", 
            "*.google.com", 
            "*"
        ],
        "connect-src": ["'self'", "*.sumup.com", "*.google.com"],
        "frame-ancestors": ["'self'"],
    }
    
    csp_header = {"Content-Security-Policy": _render_csp(csp)}
    if (
        order_payment.state == OrderPayment.PAYMENT_STATE_PENDING
        or order_payment.state == OrderPayment.PAYMENT_STATE_FAILED
    ):
        context = {
            "checkout_id": checkout_id,
            "payment": order_payment.id,
            "email": order_payment.order.email,
            "retry": order_payment.state == OrderPayment.PAYMENT_STATE_FAILED,
            "locale": _get_sumup_locale(request),
            "amount": order_payment.amount,  #CHECK IF WORKS
            "currency": order_payment.order.event.currency, #CHECK IF WORKS
            "csp_nonce": csp_nonce,
        }
    elif order_payment.state == OrderPayment.PAYMENT_STATE_CONFIRMED:
        # The payment was paid in the meantime, reload the containing page to show the success message
        context = {"reload": True, "csp_nonce": csp_nonce}
    else:
        # Invalid state, nothing to see here
        return HttpResponse(status=404)
    return TemplateResponse(
        template="pretix_sumup/payment_widget.html",
        context=context,
        request=request,
        headers=csp_header,
    )

def ideal_checkout(request, *args, **kwargs):
    provider = SumUp(request.event)
    order_payment = get_object_or_404(
        OrderPayment, pk=kwargs.get("payment"), order__event=request.event
    )

    redirect_url = provider.execute_ideal_payment(order_payment)
    return JsonResponse({'redirect_url': redirect_url})



def _get_sumup_locale(request):
    language = get_language_from_request(request)
    if language == "de" or language == "de-informal":
        return "de-DE"
    elif language == "fr":
        return "fr-FR"
    return "en-GB"
