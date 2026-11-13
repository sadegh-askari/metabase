import "metabase/auth/plugins";
import userEvent from "@testing-library/user-event";
import fetchMock from "fetch-mock";

import {
  setupCurrentUserEndpoint,
  setupLoginEndpoint,
  setupPropertiesEndpoints,
} from "__support__/server-mocks";
import { createMockSettingsState, createMockState } from "__support__/state";
import { renderWithProviders, screen, waitFor } from "__support__/ui";
import MetabaseSettings from "metabase/utils/settings";
import { createMockSettings, createMockUser } from "metabase-types/api/mocks";

import { PasswordPanel } from "./PasswordPanel";

const TEST_EMAIL = "user@example.test";
const TEST_PASSWORD = "password";

interface SetupOpts {
  isGoogleAuthEnabled?: boolean;
  isKeycloakSsoEnabled?: boolean;
}

const setup = ({
  isGoogleAuthEnabled = false,
  isKeycloakSsoEnabled = false,
}: SetupOpts = {}) => {
  const state = createMockState({
    settings: createMockSettingsState({
      "google-auth-enabled": isGoogleAuthEnabled,
      "keycloak-sso-enabled": isKeycloakSsoEnabled,
    }),
  });

  MetabaseSettings.set("google-auth-enabled", isGoogleAuthEnabled);
  MetabaseSettings.set("keycloak-sso-enabled", isKeycloakSsoEnabled);

  setupLoginEndpoint();
  setupCurrentUserEndpoint(createMockUser());
  setupPropertiesEndpoints(createMockSettings());
  renderWithProviders(<PasswordPanel />, { storeInitialState: state });
};

const cleanUp = () => {
  MetabaseSettings.set("google-auth-enabled", false);
  MetabaseSettings.set("keycloak-sso-enabled", false);
};

describe("PasswordPanel", () => {
  afterEach(() => {
    cleanUp();
  });

  it("should login successfully", async () => {
    setup();

    await userEvent.type(screen.getByLabelText("Email address"), TEST_EMAIL);
    await userEvent.type(screen.getByLabelText("Password"), TEST_PASSWORD);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Sign in" })).toBeEnabled();
    });

    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(fetchMock.callHistory.done("path:/api/session")).toBe(true);
    });
  });

  it("should render Keycloak inline and hide the forgotten-password link", () => {
    setup({ isKeycloakSsoEnabled: true });

    expect(screen.getByText("or sign in with")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Keycloak" })).toBeInTheDocument();
    expect(screen.queryByText(/forgotten my password/)).not.toBeInTheDocument();
  });
});
