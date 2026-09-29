import hashlib
import time
import uuid
from collections.abc import Callable

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.integrations.destinations import NotificationDestination
from app.integrations.schemas import DestinationConfig
from app.integrations.transport import IntegrationError
from app.storage.database import Database
from app.storage.integrations import DeliveryAttemptRecord, DeliveryRecord, DestinationRecord
from app.storage.models import utcnow


class NotificationWorker:
    def __init__(
        self,
        db: Database,
        destination: Callable[[DestinationConfig], NotificationDestination],
        *,
        notifications_enabled: bool,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db, self.destination, self.clock = db, destination, clock
        self.enabled = notifications_enabled

    def process_one(self) -> bool:
        now, claim = self.clock(), uuid.uuid4().hex
        with self.db.session() as session:
            row = session.scalar(
                select(DeliveryRecord)
                .where(
                    or_(
                        (DeliveryRecord.status.in_(["pending", "failed"]))
                        & (DeliveryRecord.next_attempt_at <= now),
                        (DeliveryRecord.status == "processing")
                        & (DeliveryRecord.claimed_until <= now),
                    )
                )
                .order_by(DeliveryRecord.created_at, DeliveryRecord.id)
                .limit(1)
            )
            if row is None:
                return False
            destination = session.get(DestinationRecord, row.destination_id)
            if destination is None:
                raise DomainError("Notification destination is missing", 500, "destination_missing")
            if destination.deleted:
                row.status, row.error = "suppressed", "destination_deleted"
                return True
            config = DestinationConfig.model_validate(destination.definition)
            if not config.enabled or (config.mode == "live" and not self.enabled):
                row.status, row.error = "suppressed", "destination_disabled"
                return True
            if row.attempt_count >= config.max_attempts:
                row.status, row.error = "dead_letter", "delivery_uncertain"
                return True
            result = session.execute(
                update(DeliveryRecord)
                .where(
                    DeliveryRecord.id == row.id,
                    DeliveryRecord.status == row.status,
                    DeliveryRecord.claimed_until == row.claimed_until,
                    DeliveryRecord.attempt_count == row.attempt_count,
                )
                .values(
                    status="processing",
                    claim=claim,
                    claimed_until=now + 60,
                    attempt_count=DeliveryRecord.attempt_count + 1,
                    last_attempt_at=utcnow(),
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                return False
            delivery_id, payload, key = row.id, row.payload, row.idempotency_key
        status: int | None = None
        error: str | None = None
        transient = False
        delay: float | None = None
        try:
            response = self.destination(config).send(payload, key)
            status = response.status
        except IntegrationError as exc:
            status, error, transient, delay = (
                exc.http_status,
                exc.code,
                exc.transient,
                exc.retry_after,
            )
        except DomainError as exc:
            error = exc.code
        with self.db.session() as session:
            row = session.get(DeliveryRecord, delivery_id)
            if row is None or row.claim != claim:
                raise DomainError(
                    "Delivery claim was lost; receiver idempotency is required",
                    409,
                    "delivery_claim",
                )
            row.http_status, row.error = status, error
            row.claim, row.claimed_until = None, 0
            session.add(
                DeliveryAttemptRecord(
                    id=uuid.uuid4().hex,
                    delivery_id=row.id,
                    number=row.attempt_count,
                    http_status=status,
                    error=error,
                )
            )
            if error is None:
                row.status, row.delivered_at = "delivered", utcnow()
            elif transient and row.attempt_count < config.max_attempts:
                row.status = "failed"
                base = config.retry_seconds * 2 ** (row.attempt_count - 1)
                jitter = (int(hashlib.sha256(key.encode()).hexdigest()[:4], 16) % 1000) / 5000
                row.next_attempt_at = self.clock() + (
                    delay if delay is not None else base * (1 + jitter)
                )
            else:
                row.status = "dead_letter"
        return True


def suppress_pending(session: Session, destination_id: str) -> None:
    session.execute(
        update(DeliveryRecord)
        .where(
            DeliveryRecord.destination_id == destination_id,
            DeliveryRecord.status.in_(["pending", "failed"]),
        )
        .values(status="suppressed", error="destination_disabled")
    )
