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

  // Test 1: Create client
  console.log('Test 1: Create client');
  const client = new SigilClient();
  console.log('✓ Client created');
  console.log();

  // Test 2: Try to connect (will fail if daemon not running)
  console.log('Test 2: Connect to daemon');
  try {
    await client.connect();
    console.log('✓ Connected to daemon');
    console.log();

    // If connected, try basic operations
    console.log('Test 3: Check if secret exists');
    const exists = await client.exists('test/secret');
    console.log(`✓ exists('test/secret') = ${exists}`);
    console.log();

    console.log('Test 4: List secrets');
    const secrets = await client.list('');
    console.log(`✓ Found ${secrets.length} secrets`);
    console.log();

    console.log('All tests passed!');
  } catch (e) {
    console.log(`✗ Connection failed (expected if daemon not running): ${e.message}`);
    console.log();
    console.log('SDK loaded successfully. Integration tests require running daemon.');
  }
}

test().catch(console.error);
