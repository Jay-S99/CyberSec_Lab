import sqlite3
from functools import wraps

from flask import abort, current_app, g, has_request_context

from auth.login import require_login
from database import get_db
from seed import CLASSIFICATIONS, DOSSIER_STATUSES, PERMISSIONS, ROLES


PERMISSION_NAMES = frozenset(name for name, _description in PERMISSIONS)
ROLE_NAMES = frozenset(name for name, _description in ROLES)
WORKING_STATUSES = frozenset({"DRAFT", "REJECTED"})
REVIEW_STATUSES = frozenset({"PENDING", "SUBMITTED", "APPROVED"})


def _field(record, name):
    try:
        return record[name]
    except (KeyError, IndexError, TypeError):
        return None


def _current_user():
    if not has_request_context() or g.get("password_change_required", True):
        return None
    user_id = _field(g.get("user"), "id")
    session = g.get("auth_session")
    if (
        type(user_id) is not int
        or user_id <= 0
        or _field(session, "user_id") != user_id
    ):
        return None
    try:
        user = get_db().execute(
            """
            SELECT users.id, users.role_id, roles.name AS role_name
            FROM users JOIN roles ON roles.id = users.role_id
            WHERE users.id = ? AND users.is_active = 1 AND users.is_blocked = 0
              AND users.deleted_at IS NULL
            """,
            (user_id,),
        ).fetchone()
    except sqlite3.Error:
        current_app.logger.error("Authorization data could not be read.")
        return None
    if (
        user is None
        or user["role_name"] not in ROLE_NAMES
        or user["role_id"] != _field(session, "role_id_at_creation")
    ):
        return None
    return user


def get_role_permissions(connection, role_id):
    rows = connection.execute(
        """
        SELECT roles.name AS role_name, permissions.name AS permission_name
        FROM roles
        LEFT JOIN role_permissions ON role_permissions.role_id = roles.id
        LEFT JOIN permissions ON permissions.id = role_permissions.permission_id
        WHERE roles.id = ?
        """,
        (role_id,),
    ).fetchall()
    if not rows or any(row["role_name"] not in ROLE_NAMES for row in rows):
        return frozenset()
    names = frozenset(
        row["permission_name"] for row in rows
        if row["permission_name"] is not None
    )
    return names if names <= PERMISSION_NAMES else frozenset()


def get_user_permissions():
    user = _current_user()
    if user is None:
        return frozenset()
    try:
        return get_role_permissions(get_db(), user["role_id"])
    except sqlite3.Error:
        current_app.logger.error("Permission data could not be read.")
        return frozenset()


def has_permission(permission):
    return (
        isinstance(permission, str)
        and permission in PERMISSION_NAMES
        and permission in get_user_permissions()
    )


def deny_access(operation):
    g.authorization_operation = operation
    abort(403)


def require_permission(permission):
    operation = (
        permission
        if isinstance(permission, str) and permission in PERMISSION_NAMES
        else "unknown"
    )

    def decorate(view):
        @require_login
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not has_permission(permission):
                deny_access(operation)
            return view(*args, **kwargs)

        return wrapped

    return decorate


def is_resource_owner(resource):
    owner_id = _field(resource, "created_by")
    if type(owner_id) is not int or owner_id <= 0:
        return False
    user = _current_user()
    return user is not None and owner_id == user["id"]


def _valid_dossier(dossier):
    classification = _field(dossier, "classification")
    status = _field(dossier, "status")
    return (
        isinstance(classification, str)
        and classification in CLASSIFICATIONS
        and isinstance(status, str)
        and status in DOSSIER_STATUSES
    )


def can_access_dossier(dossier):
    if not _valid_dossier(dossier):
        return False
    permissions = get_user_permissions()
    classification = dossier["classification"]
    status = dossier["status"]
    if classification == "DECLASSIFIED" or status == "DECLASSIFIED":
        return (
            classification == status == "DECLASSIFIED"
            and "dossiers.read_declassified" in permissions
        )
    if classification == "DOOM_LEVEL":
        return (
            {"dossiers.read_classified", "dossiers.read_doom_level"}
            <= permissions
            and status in REVIEW_STATUSES
        )
    if status in WORKING_STATUSES:
        return (
            "dossiers.read_own_drafts" in permissions
            and is_resource_owner(dossier)
        )
    return (
        status in REVIEW_STATUSES
        and "dossiers.read_classified" in permissions
    )


def _can_change_owned_dossier(dossier, permission):
    return (
        _valid_dossier(dossier)
        and dossier["classification"] not in {"DECLASSIFIED", "DOOM_LEVEL"}
        and dossier["status"] in WORKING_STATUSES
        and has_permission(permission)
        and is_resource_owner(dossier)
    )


def can_edit_dossier(dossier):
    return _can_change_owned_dossier(dossier, "dossiers.edit_own")


def can_submit_dossier(dossier):
    return _can_change_owned_dossier(dossier, "dossiers.submit_own")


def can_view_incident(incident):
    return has_permission("incidents.read_own") and is_resource_owner(incident)
