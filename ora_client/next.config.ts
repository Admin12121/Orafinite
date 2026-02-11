import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployment
  output: "standalone",

  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "assets.invoicely.gg",
      },
      {
        protocol: "https",
        hostname: "dqy38fnwh4fqs.cloudfront.net",
      },
      {
        protocol: "https",
        hostname: "d26c7l40gvbbg2.cloudfront.net",
      },
    ],
  },
};

export default nextConfig;
