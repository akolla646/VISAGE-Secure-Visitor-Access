# =====================================================
# AUTHORIZATION – ACCESS CONTROL LIST (ACL)
# Satisfies:
# • Access Control Model (ACL)
# • Policy Definition & Justification
# =====================================================

# Subjects (roles): visitor, host, admin
# Objects / actions: request_access, approve_request, view_users
ACL = {
    "visitor": ["request_access"],   # Visitor can only request access
    "host": ["approve_request"],     # Host can approve visitor requests
    "admin": ["view_users"]          # Admin can view all registered users
}

def check_access(role, action):
    """
    Enforces access control programmatically
    Satisfies: Implementation of Access Control
    """
    return action in ACL.get(role, [])
