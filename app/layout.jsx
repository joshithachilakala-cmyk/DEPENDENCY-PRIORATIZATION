import "./globals.css";

export const metadata = {
  title: "Dependency Prioritizer | Contextual Vulnerability Risk Engine",
  description:
    "Intelligent dependency vulnerability prioritization engine for software development teams. Ingest scan reports, calculate contextual composite risk, and generate actionable remediation guidance.",
  keywords: ["cybersecurity", "vulnerability prioritization", "CVE", "CVSS", "SCA", "OWASP", "dependency check"],
};

export const viewport = {
  themeColor: "#070a11",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@500;600;700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
