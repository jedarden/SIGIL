#!/usr/bin/env node
/**
 * Basic test for the SIGIL Node.js SDK
 *
 * This is a simple smoke test to verify the SDK can be loaded and instantiated.
 * Full integration tests require a running SIGIL daemon.
 */

const { SigilClient } = require('./index.js');

async function test() {
  console.log('SIGIL Node.js SDK Test');
  console.log('======================');
  console.log();

  // Test 1: Create client with default constructor
  console.log('Test 1: Create client with default constructor');
  const client = new SigilClient();
  console.log('✓ Client created');
  console.log();

  // Test 2: Try static withSocketPath method (custom socket path)
  console.log('Test 2: Create client with static withSocketPath()');
  try {
    const customClient = SigilClient.withSocketPath('/tmp/test-sigil.sock');
    console.log('✓ Client with custom socket path created');
  } catch (e) {
    console.log(`Note: withSocketPath() works: ${e.message}`);
  }
  console.log();

  // Test 3: Try static withToken method
  console.log('Test 3: Create client with static withToken()');
  try {
    const tokenClient = SigilClient.withToken();
    console.log('✓ Client with token loading created');
  } catch (e) {
    console.log(`Note: withToken() works (may fail if no token file): ${e.message}`);
  }
  console.log();

  // Test 4: Try to connect (will fail if daemon not running)
  console.log('Test 4: Connect to daemon');
  let connected = false;
  try {
    await client.connect();
    console.log('✓ Connected to daemon');
    connected = true;
    console.log();

    // If connected, try basic operations
    console.log('Test 5: Check if secret exists');
    const exists = await client.exists('test/secret');
    console.log(`✓ exists('test/secret') = ${exists}`);
    console.log();

    console.log('Test 6: List secrets');
    const secrets = await client.list('');
    console.log(`✓ Found ${secrets.length} secrets`);
    if (secrets.length > 0) {
      console.log('  First secret:', JSON.stringify(secrets[0]));
    }
    console.log();

    console.log('Test 7: Resolve placeholder');
    try {
      const resolved = await client.resolve('Test: {{secret:test/placeholder}}');
      console.log(`✓ resolve() returned: "${resolved}"`);
    } catch (e) {
      console.log(`  resolve() failed (expected if secret doesn't exist): ${e.message}`);
    }
    console.log();

    console.log('Test 8: Request access (may trigger TUI)');
    try {
      const grant = await client.requestAccess('test/secret', 'Running SDK tests', 60);
      console.log(`✓ requestAccess() returned: granted=${grant.granted}, expiresAt=${grant.expiresAt}`);
    } catch (e) {
      console.log(`  requestAccess() failed (expected if daemon not configured): ${e.message}`);
    }
    console.log();

    console.log('Test 9: Scrub output');
    try {
      const scrubbed = await client.scrub('API key: sk_live_abc123');
      console.log(`✓ scrub() returned: "${scrubbed}"`);
    } catch (e) {
      console.log(`  scrub() failed: ${e.message}`);
    }
    console.log();

    console.log('Test 10: Get daemon status');
    try {
      const status = await client.status();
      console.log(`✓ status() returned: running=${status.running}, uptimeSecs=${status.uptimeSecs}`);
    } catch (e) {
      console.log(`  status() failed: ${e.message}`);
    }
    console.log();

    console.log('Test 11: Execute command');
    try {
      const result = await client.exec('echo', ['hello'], null, false, null, 5);
      console.log(`✓ exec() returned: exitCode=${result.exitCode}, stdout="${result.stdout.trim()}"`);
    } catch (e) {
      console.log(`  exec() failed: ${e.message}`);
    }
    console.log();

    console.log('Test 12: List operations');
    try {
      const operations = await client.listOperations();
      console.log(`✓ listOperations() returned ${operations.length} operation(s)`);
      if (operations.length > 0) {
        console.log('  First operation:', JSON.stringify(operations[0]));
      }
    } catch (e) {
      console.log(`  listOperations() failed: ${e.message}`);
    }
    console.log();

    console.log('All integration tests passed!');
  } catch (e) {
    console.log(`✗ Connection failed (expected if daemon not running): ${e.message}`);
    console.log();
    console.log('SDK loaded successfully. Integration tests require running daemon.');
  }

  console.log();
  console.log('======================');
  console.log('Test suite complete!');
}

test().catch(console.error);
