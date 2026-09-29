import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Container Image CVE Dashboard",
  description:
    "Compare CVE findings across container images using trivy and grype scanners",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
