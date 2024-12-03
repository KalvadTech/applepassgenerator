from typing import Any, Dict

from applepassgenerator.models import ApplePass


class ApplePassGeneratorClient:
    """Client for generating Apple Wallet passes.

    This class handles the creation of Apple Wallet passes with the required identifiers
    and organization information.

    Args:
        team_identifier (str): The Apple Developer Team identifier
        pass_type_identifier (str): The Pass Type identifier registered with Apple
        organization_name (str): The name of the organization issuing the pass
    """

    def __init__(
        self,
        team_identifier: str,
        pass_type_identifier: str,
        organization_name: str,
    ) -> None:
        self.team_identifier = team_identifier
        self.pass_type_identifier = pass_type_identifier
        self.organization_name = organization_name

    def get_pass(self, card_info: Dict[str, Any]) -> ApplePass:
        """Creates an Apple Wallet pass with the provided card information.

        Args:
            card_info (Dict[str, Any]): Dictionary containing the pass content and styling

        Returns:
            ApplePass: A configured Apple Wallet pass object ready for generation

        Raises:
            ValueError: If required fields are missing in card_info
        """
        if not isinstance(card_info, dict):
            raise ValueError("card_info must be a dictionary")

        return ApplePass(
            card_info,
            pass_type_identifier=self.pass_type_identifier,
            organization_name=self.organization_name,
            team_identifier=self.team_identifier,
        )
