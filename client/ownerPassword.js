import { io } from 'socket.io-client';

// Simple client example showing how to display room owner password
const socket = io('https://localhost:4000');

socket.on('room:owner_password', ({ roomId, password }) => {
  console.log(`Owner password for room ${roomId}: ${password}`);
  // Here the UI could display the password to owners/sysops/admins.
});

export default socket;
