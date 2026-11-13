import { t } from "ttag";

import { AuthCardButton, AuthTextButton } from "../AuthButton";

interface KeycloakButtonProps {
  isCard?: boolean;
  redirectUrl?: string;
}

export const KeycloakButton = ({
  isCard = false,
  redirectUrl,
}: KeycloakButtonProps) => {
  const handleClick = () => {
    const target = new URL("/auth/sso/keycloak", window.location.origin);
    if (redirectUrl) {
      target.searchParams.set("redirect", redirectUrl);
    }
    window.location.assign(target.href);
  };

  const label = t`Sign in with Keycloak`;
  return isCard ? (
    <AuthCardButton onClick={handleClick}>{label}</AuthCardButton>
  ) : (
    <AuthTextButton onClick={handleClick}>{label}</AuthTextButton>
  );
};
