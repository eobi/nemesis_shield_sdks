import { withShield } from "@nemesis-shield-autogon/edge";
import { NextResponse } from "next/server";

// Guards every route. Positive-security WAF, observe mode until a baseline is approved,
// fail-open if Nemesis is unreachable. Do not narrow the matcher to skip auth'd routes.
export const config = { matcher: "/:path*" };

export default withShield(() => NextResponse.next(), {
  token: process.env.NEMESIS_TOKEN,
});
