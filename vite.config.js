import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(() => {

  return {
    // Define global constants for the environment variables
    plugins: [
      react()
    ],
    server: {
      port: 3000,
    },
  }
});
