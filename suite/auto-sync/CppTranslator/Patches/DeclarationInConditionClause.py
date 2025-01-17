from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class DeclarationInConditionalClause(Patch):
    """
    Patch   if (DECLARATION) ...
    to      DECLARATION
            if (VAR) ...
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(if_statement"
            "   (condition_clause"
            "       (declaration"
            "           (_)"
            "           ((identifier) @id)"
            "           (_)"
            "       ) @decl"
            "   )"
            "   (_) @if_body"
            ") @condition_clause"
        )

    def get_main_capture_name(self) -> str:
        return "condition_clause"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        declaration = captures[1][0]
        identifier = captures[2][0]
        if_body = captures[3][0]
        identifier = get_text(src, identifier.start_byte, identifier.end_byte)
        declaration = get_text(src, declaration.start_byte, declaration.end_byte)
        if_body = get_text(src, if_body.start_byte, if_body.end_byte)
        res = declaration + b";\nif (" + identifier + b")\n" + if_body
        return res
