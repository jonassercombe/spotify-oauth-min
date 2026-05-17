module.exports = {
  apps: [
    {
      name: "playlistpilot",
      script: "node_modules/next/dist/bin/next",
      args: "start -p 3020",
      cwd: "/var/www/playlistpilot/current",
      env: {
        NODE_ENV: "production",
        PORT: "3020",
      },
      max_memory_restart: "512M",
    },
  ],
};
