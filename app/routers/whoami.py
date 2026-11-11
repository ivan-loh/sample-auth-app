from fastapi import APIRouter

from app.auth import AUTH_ERROR_RESPONSES, ReadPrincipalDep
from app.schemas import WhoAmIResponse

router = APIRouter(tags=["whoami"], responses=AUTH_ERROR_RESPONSES)


@router.get("/whoami")
def read_whoami(principal: ReadPrincipalDep) -> WhoAmIResponse:
    return WhoAmIResponse(
        tenant_id=principal.tenant_id,
        object_id=principal.object_id,
        name=principal.name,
        username=principal.username,
        scopes=sorted(principal.scopes),
        client_id=principal.client_id,
    )
