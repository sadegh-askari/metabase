import "metabase/auth/plugins";
import { screen } from "__support__/ui";

import { setup } from "./setup";

describe("Login", () => {
  it("should show the password form and providers in one login panel", () => {
    setup({ isPasswordLoginEnabled: true, isGoogleAuthEnabled: true });

    expect(screen.getByLabelText("Email address")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText("Sign in with Google")).toBeInTheDocument();
  });

  it("should render the panel of the selected provider", () => {
    setup({
      initialRoute: "/auth/login/password",
      isPasswordLoginEnabled: true,
      isGoogleAuthEnabled: true,
    });

    expect(screen.getByRole("button")).toBeInTheDocument();
  });

  it("should implicitly select the only provider with a panel", () => {
    setup({
      isPasswordLoginEnabled: true,
      isGoogleAuthEnabled: false,
    });

    expect(screen.getByRole("button")).toBeInTheDocument();
  });

  it("should not disable password login for OSS", () => {
    setup({ isPasswordLoginEnabled: false, isGoogleAuthEnabled: true });

    expect(screen.getByText("Sign in with email")).toBeInTheDocument();
  });
});
