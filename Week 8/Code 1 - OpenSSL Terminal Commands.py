# Step 1: Generate a 2048-bit RSA private key
openssl genrsa -out private.key 2048

# Step 2: Generate a Certificate Signing Request (CSR)
openssl req -new -key private.key -out request.csr

# Step 3: Self-sign the certificate (valid for 365 days)
openssl req -x509 -days 365 -key private.key -in request.csr -out certificate.pem

# Step 4: Inspect the certificate details
openssl x509 -in certificate.pem -text -noout

# Step 5: Download and inspect a live website certificate
openssl s_client -connect www.google.com:443 -showcerts < /dev/null 2>/dev/null \
  | openssl x509 -text -noout
