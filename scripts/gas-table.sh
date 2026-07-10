#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Prints a markdown gas-comparison table for both verifier entry points across EVM
# versions (see foundry.toml profiles). Numbers are execution gas of the internal
# library call measured by foundry-test/SchnorrVerifierGas.t.sol.

printf '| EVM version | `verify` (modexp lift) | `verifyWithNonceY` (witness) | saved |\n'
printf '| ----------- | ---------------------- | ---------------------------- | ----- |\n'

for profile in default prague osaka; do
    output="$(
        FOUNDRY_PROFILE="$profile" forge test \
            --root "$ROOT" \
            --match-contract SchnorrVerifierGasTest \
            -vv 2>/dev/null
    )"

    modexpPathGas="$(printf '%s' "$output" | sed -n 's/.*verify (modexp lift) execution gas: //p')"
    witnessPathGas="$(printf '%s' "$output" | sed -n 's/.*verifyWithNonceY (witness) execution gas: //p')"
    savedGas="$(printf '%s' "$output" | sed -n 's/.*execution gas saved: //p')"

    if [ -z "$modexpPathGas" ] || [ -z "$witnessPathGas" ]; then
        echo "error: gas benchmark did not produce output for profile '$profile'" >&2
        exit 1
    fi

    label="$profile"
    if [ "$profile" = "default" ]; then
        label="paris (default)"
    fi

    printf '| %s | %s | %s | %s |\n' "$label" "$modexpPathGas" "$witnessPathGas" "$savedGas"
done
