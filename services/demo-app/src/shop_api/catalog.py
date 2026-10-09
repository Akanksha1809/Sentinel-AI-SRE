"""In-memory product catalogue and checkout logic.

Release defect `checkout_null_price` simulates a bad data migration shipped in
release 1.1.0: products 6-10 lose their price, so checkout for them raises a
TypeError. The failure is fully deterministic for a given request mix.
"""

from __future__ import annotations

from dataclasses import dataclass

from shop_api.config import ReleaseDefect

_BASE_PRICES_CENTS: dict[int, int] = {
    1: 1299,
    2: 2599,
    3: 499,
    4: 8999,
    5: 1999,
    6: 3499,
    7: 749,
    8: 15999,
    9: 2299,
    10: 999,
}
_NULLED_BY_DEFECT = frozenset({6, 7, 8, 9, 10})


@dataclass(frozen=True, slots=True)
class Product:
    id: int
    name: str
    price_cents: int | None


class Catalog:
    def __init__(self, defect: ReleaseDefect = "none") -> None:
        self._products: dict[int, Product] = {}
        for pid, price in _BASE_PRICES_CENTS.items():
            nulled = defect == "checkout_null_price" and pid in _NULLED_BY_DEFECT
            self._products[pid] = Product(pid, f"product-{pid}", None if nulled else price)

    def list(self) -> list[Product]:
        return list(self._products.values())

    def get(self, product_id: int) -> Product | None:
        return self._products.get(product_id)

    def checkout_total(self, product: Product, quantity: int) -> int:
        # Deliberately no None-guard: the broken release must fail the way a real
        # regression would, with an unhandled TypeError and a stack trace in the logs.
        return product.price_cents * quantity  # type: ignore[operator]
