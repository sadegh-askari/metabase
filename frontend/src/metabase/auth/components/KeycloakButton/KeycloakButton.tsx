// eslint-disable-next-line eslint-js/no-restricted-imports
import styled from "@emotion/styled";
import { t } from "ttag";

import { Icon, UnstyledButton } from "metabase/ui";

interface KeycloakButtonProps {
  isCard?: boolean;
  redirectUrl?: string;
}

export const KeycloakButton = ({
  redirectUrl,
}: KeycloakButtonProps) => {
  const handleClick = () => {
    const target = new URL("/auth/sso/keycloak", window.location.origin);
    if (redirectUrl) {
      target.searchParams.set("redirect", redirectUrl);
    }
    window.location.assign(target.href);
  };

  return (
    <Button onClick={handleClick} type="button">
      <Icon
        name="key"
        size={16}
        style={{ color: "#e3a23b" }}
        aria-hidden="true"
      />
      <span>{t`Keycloak`}</span>
    </Button>
  );
};

const Button = styled(UnstyledButton)`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  min-height: 2.125rem;
  padding: 0.4rem 0.75rem;
  border-radius: 4px;
  background-color: #414247;
  color: #f5f5f5;
  font-size: 0.875rem;
  font-weight: 700;
  line-height: 1.25rem;
  transition: background-color 120ms ease;

  &:hover {
    background-color: #505156;
  }

  &:focus-visible {
    outline: 2px solid var(--mb-color-core-brand);
    outline-offset: 2px;
  }
`;
