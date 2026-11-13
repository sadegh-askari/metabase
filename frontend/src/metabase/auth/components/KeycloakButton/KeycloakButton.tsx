// eslint-disable-next-line eslint-js/no-restricted-imports
import styled from "@emotion/styled";
import { t } from "ttag";

import { UnstyledButton } from "metabase/ui";

import keycloakIcon from "./keycloak.png";

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
      <img src={keycloakIcon} alt="" aria-hidden="true" />
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
  height: 40px;
  padding: 12px 16px;
  border: 0.5px solid transparent;
  border-radius: 8px;
  background-color: #414247;
  color: #f5f5f5;
  font-family: var(--mb-default-font-family);
  font-size: var(--mantine-font-size-md);
  font-weight: 700;
  line-height: 16px;
  box-shadow: var(--mantine-shadow-xs);
  transition: background-color 120ms ease;

  img {
    width: 16px;
    height: 16px;
    object-fit: contain;
  }

  &:hover {
    background-color: #505156;
  }

  &:active {
    background-color: #38393d;
  }

  &:focus-visible {
    outline: 2px solid var(--mb-color-core-brand);
    outline-offset: 2px;
  }
`;
