import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: "/Users/sobanahmad/Fast-Nuces/Semester 7/infosec/finalProj",

  // Exclude Node.js built-in modules from client-side bundles
  // This prevents MongoDB and other server-only modules from being bundled for the browser
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        net: false,
        tls: false,
        fs: false,
        dns: false,
        child_process: false,
        os: false,
        path: false,
        crypto: false,
      };
    }
    return config;
  },
};

export default nextConfig;
