from app.models import User


def get_user_contact(session, user_id: int) -> dict[str, str | None]:
    user = session.query(User).filter_by(id=user_id).one()
    return {"email": user.email, "phone": user.phone_number}
