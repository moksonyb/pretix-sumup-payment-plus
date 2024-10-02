import requests
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import logging

SUMUP_BASE_URL = "https://api.sumup.com/v0.1"

logger = logging.getLogger("pretix.plugins.sumup")

def _auth_header(access_token):
    return {"Authorization": "Bearer " + access_token}


class SumupApiError(Exception):
    def __init__(self, message, error_code, param):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.param = param

    def __str__(self):
        exception_str = f"{self.error_code} - {self.message}"
        if self.param:
            exception_str += f" ({self.param})"
        return exception_str


def _handle_response_status(response):
    # Handle 4xx errors
    if response.status_code // 100 == 4:
        response_body = response.json()
        raise SumupApiError(
            response_body.get("message") or response.get("error_message") or "",
            response_body.get("error_code"),
            response_body.get("param"),
        )

    # Forward other errors
    response.raise_for_status()


def validate_access_token_and_get_merchant_code(access_token):
    if not access_token:
        raise ValidationError(_("No API Key given."))

    response = requests.get(f"{SUMUP_BASE_URL}/me", headers=_auth_header(access_token))

    if response.status_code == 401:
        raise ValidationError(_("The API Key is invalid."))

    _handle_response_status(response)
    response_body = response.json()
    return response_body["merchant_profile"]["merchant_code"]


def create_checkout(
    amount,
    currency,
    checkout_reference,
    description,
    merchant_code,
    return_url,
    redirect_url,
    access_token,
    first_name = "",
    last_name = "",
    email = "",
    country = "",
    city = "",
    line1 = "",
    line2 = "",
    postal_code = "",
    state = "",
):
    logger.info("Creating SumUp checkout")
    logger.info(first_name)

    response = requests.post(
        f"{SUMUP_BASE_URL}/checkouts",
        json={
            "checkout_reference": checkout_reference,
            "description": description,
            "amount": float(amount),
            "currency": currency,
            "merchant_code": merchant_code,
            "return_url": return_url,
            "redirect_url": redirect_url,
            "personal_details": {
                "address": {
                    "city": city,
                    "country": country,
                    "line1": line1,
                    "line2": line2,
                    "postal_code": postal_code,
                    "state": state,
                    },
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                },
        },
        headers=_auth_header(access_token),
    )
    _handle_response_status(response)

    response_body = response.json()
    return response_body["id"]

def get_payment_methods(checkout_id, access_token):
    response = requests.get(
        f"{SUMUP_BASE_URL}/checkouts/{checkout_id}/payment-methods",
        headers=_auth_header(access_token),
    )
    _handle_response_status(response)

    response_body = response.json()
    return response_body

def get_checkout(checkout_id, access_token):
    response = requests.get(
        f"{SUMUP_BASE_URL}/checkouts/{checkout_id}", headers=_auth_header(access_token)
    )
    _handle_response_status(response)

    response_body = response.json()
    return response_body


def cancel_checkout(checkout_id, access_token):
    response = requests.delete(
        f"{SUMUP_BASE_URL}/checkouts/{checkout_id}", headers=_auth_header(access_token)
    )
    _handle_response_status(response)

def process_ideal_checkout(checkout_id, access_token):
    response = requests.put(
        f"{SUMUP_BASE_URL}/checkouts/{checkout_id}",
        json={"payment_type": "ideal"},
        headers=_auth_header(access_token),
    )
    _handle_response_status(response)

    response_body = response.json()
    return response_body["next_step"]["full"]

def get_transaction(transaction_id, access_token):
    response = requests.get(
        f"{SUMUP_BASE_URL}/me/transactions/",
        params={"id": transaction_id},
        headers=_auth_header(access_token),
    )

    _handle_response_status(response)

    response_body = response.json()
    return response_body


def refund_transaction(transaction_id, access_token, amount=None):
    response = requests.post(
        f"{SUMUP_BASE_URL}/me/refund/{transaction_id}",
        json={"amount": float(amount)} if amount else None,
        headers=_auth_header(access_token),
    )

    _handle_response_status(response)
