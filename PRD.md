Product Requirements Document (PRD): GhostDrop


1. The Problem
Users need a straightforward way to share sensitive data, such as passwords or API keys, safely and without the friction of setting up an account. While one-time viewing tools exist (like 1time.io), their primary drawback is that only the person who opens the link first can see the secret. This limitation makes it impossible to share a single, secure link with multiple authorized individuals, such as an entire team or family members.

2. Product Overview
GhostDrop is a secure, frictionless web application that allows users to share encrypted data with a specific "multi-view" constraint. By combining server-side authority with client-side friction, it allows a predefined number of legitimate views while actively preventing a single user from maliciously burning through the allocated limit by refreshing the page.

3. How It Works
Zero-Knowledge Setup: When a sender inputs a secret and specifies an exact view limit and expiry date, the browser immediately encrypts the data locally using the WebCrypto API. This ensures the backend never sees the plaintext secret.
Ticket Dispensing: The encrypted blob is stored on the backend, which simultaneously generates a Redis List containing the exact number of single-use access tokens requested. A Redis TTL (Time To Live) is set to guarantee physical deletion of the data at the user's chosen expiry date.
Link Generation: The sender receives a shareable URL where the decryption key is safely hidden within the URL hash (e.g., shatterlink.com/view/123#key456).
The Poison Check: When a recipient clicks the link, the frontend aggressively checks their LocalStorage and IndexedDB for a "poisoned" JWT associated with that specific secret ID. If a valid JWT is found, the frontend intercepts the request and physically prevents the API call from firing.
Decryption & Poisoning: If the recipient's browser is clean, the API call fires, the server pops one token off the Redis List (permanently deleting it), and returns the payload. The browser decrypts the payload locally using the URL hash key, while simultaneously writing a newly minted, signed JWT into both LocalStorage and IndexedDB to "poison" that device against future view attempts.
Final Destruction: Once the Redis List reaches 0 tokens, the encrypted blob is completely wiped from the database entirely.

4. User Story
As a backend engineering lead,I want to securely share a production API key with three specific developers using a single link,so that they can all access it effortlessly without creating accounts, and I can trust that the data will be permanently wiped from the server the moment the third developer views it.