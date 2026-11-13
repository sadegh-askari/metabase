// eslint-disable-next-line eslint-js/no-restricted-imports
import styled from "@emotion/styled";

export const ActionList = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  margin-top: 1rem;
`;

export const ActionListItem = styled.div`
  width: 100%;

  &:not(:last-child) {
    margin-bottom: 0.75rem;
  }
`;

export const ActionListDivider = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  margin-bottom: 0.75rem;
  color: var(--mb-color-text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
  line-height: 1rem;
  white-space: nowrap;

  &::before,
  &::after {
    content: "";
    flex: 1;
    height: 1px;
    background-color: var(--mb-color-border);
  }
`;
