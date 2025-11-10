import streamlit as st
from typing import Dict, Any

# Internal helpers to support both new and old Streamlit APIs
def _has_query_params_attr() -> bool:
    return hasattr(st, "query_params")

def get_query_params() -> Dict[str, Any]:
    if _has_query_params_attr():
        try:
            return dict(st.query_params)
        except Exception:
            return {}
    # Fallback for older Streamlit versions
    try:
        qp = st.experimental_get_query_params()
        # experimental_get_query_params returns list values
        return {k: (v[0] if isinstance(v, list) and v else v) for k, v in qp.items()}
    except Exception:
        return {}

def set_query_params(params: Dict[str, Any]) -> None:
    if not params:
        return
    if _has_query_params_attr():
        try:
            st.query_params.update(params)
            return
        except Exception:
            pass
    # Fallback
    try:
        st.experimental_set_query_params(**params)
    except Exception:
        pass

def clear_query_params() -> None:
    if _has_query_params_attr():
        try:
            st.query_params.clear()
            return
        except Exception:
            pass
    # Fallback clears by setting none
    try:
        st.experimental_set_query_params()
    except Exception:
        pass

def save_session_to_query_params() -> None:
    """Save session data to URL query parameters for persistence."""
    token = st.session_state.get("authentication_token")
    if token:
        set_query_params({
            "token": token,
            "username": st.session_state.get("current_username", ""),
            "role": st.session_state.get("user_role", "user"),
        })

def restore_session_from_query_params() -> bool:
    """Restore session data from URL query parameters."""
    try:
        qp = get_query_params()
        token = qp.get("token")
        if token:
            # Only restore if not already set
            if not st.session_state.get("authentication_token"):
                st.session_state.authentication_token = token
                st.session_state.current_username = qp.get("username", "")
                st.session_state.user_role = qp.get("role", "user")
            return True
    except Exception:
        pass
    return False

def clear_session() -> None:
    """Clear both session state and query parameters."""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    clear_query_params()
