% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/vault_client_transit.R
\name{vault_client_transit}
\alias{vault_client_transit}
\title{Transit Engine}
\description{
Transit Engine

Transit Engine
}
\details{
Interact with vault's \code{transit} engine.  This is useful for
encrypting arbitrary data without storing it in the vault - like
"cryptography as a service" or "encryption as a service". The
transit secrets engine can also sign and verify data; generate
hashes and HMACs of data; and act as a source of random bytes.
See
https://developer.hashicorp.com/vault/docs/secrets/transit
for an introduction to the capabilities of the \code{transit}
engine.
}
\examples{
server <- vaultr::vault_test_server(if_disabled = message)
if (!is.null(server)) {
  client <- server$client()

  client$secrets$enable("transit")
  transit <- client$secrets$transit

  # Before encrypting anything, create a key.  Note that it will
  # not be returned to you, and is accessed purely by name
  transit$key_create("test")

  # Some text to encrypt
  plaintext <- "hello world"

  # Encrypted:
  cyphertext <- transit$data_encrypt("test", charToRaw(plaintext))

  # Decrypt the data
  res <- transit$data_decrypt("test", cyphertext)
  rawToChar(res)

  # This approach works with R objects too, if used with serialise.
  # First, serialise an R object to a raw vector:
  data <- serialize(mtcars, NULL)

  # Then encrypt this data:
  enc <- transit$data_encrypt("test", data)

  # The resulting string can be safely passed around (e.g., over
  # email) or written to disk, and can later be decrypted by
  # anyone who has access to the "test" key in the vault:
  data2 <- transit$data_decrypt("test", enc)

  # Once decrypted, the data can be "unserialised" back into an R
  # object:
  unserialize(data2)

  # cleanup
  server$kill()
}
}
\section{Super class}{
\code{\link[vaultr:vault_client_object]{vaultr::vault_client_object}} -> \code{vault_client_transit}
}
\section{Methods}{
\subsection{Public methods}{
\itemize{
\item \href{#method-vault_client_transit-new}{\code{vault_client_transit$new()}}
\item \href{#method-vault_client_transit-custom_mount}{\code{vault_client_transit$custom_mount()}}
\item \href{#method-vault_client_transit-key_create}{\code{vault_client_transit$key_create()}}
\item \href{#method-vault_client_transit-key_read}{\code{vault_client_transit$key_read()}}
\item \href{#method-vault_client_transit-key_list}{\code{vault_client_transit$key_list()}}
\item \href{#method-vault_client_transit-key_delete}{\code{vault_client_transit$key_delete()}}
\item \href{#method-vault_client_transit-key_update}{\code{vault_client_transit$key_update()}}
\item \href{#method-vault_client_transit-key_rotate}{\code{vault_client_transit$key_rotate()}}
\item \href{#method-vault_client_transit-key_export}{\code{vault_client_transit$key_export()}}
\item \href{#method-vault_client_transit-data_encrypt}{\code{vault_client_transit$data_encrypt()}}
\item \href{#method-vault_client_transit-data_decrypt}{\code{vault_client_transit$data_decrypt()}}
\item \href{#method-vault_client_transit-data_rewrap}{\code{vault_client_transit$data_rewrap()}}
\item \href{#method-vault_client_transit-datakey_create}{\code{vault_client_transit$datakey_create()}}
\item \href{#method-vault_client_transit-random}{\code{vault_client_transit$random()}}
\item \href{#method-vault_client_transit-hash}{\code{vault_client_transit$hash()}}
\item \href{#method-vault_client_transit-hmac}{\code{vault_client_transit$hmac()}}
\item \href{#method-vault_client_transit-sign}{\code{vault_client_transit$sign()}}
\item \href{#method-vault_client_transit-verify_signature}{\code{vault_client_transit$verify_signature()}}
\item \href{#method-vault_client_transit-verify_hmac}{\code{vault_client_transit$verify_hmac()}}
\item \href{#method-vault_client_transit-key_backup}{\code{vault_client_transit$key_backup()}}
\item \href{#method-vault_client_transit-key_restore}{\code{vault_client_transit$key_restore()}}
\item \href{#method-vault_client_transit-key_trim}{\code{vault_client_transit$key_trim()}}
}
}
\if{html}{\out{
<details open><summary>Inherited methods</summary>
<ul>
<li><span class="pkg-link" data-pkg="vaultr" data-topic="vault_client_object" data-id="format"><a href='../../vaultr/html/vault_client_object.html#method-vault_client_object-format'><code>vaultr::vault_client_object$format()</code></a></span></li>
<li><span class="pkg-link" data-pkg="vaultr" data-topic="vault_client_object" data-id="help"><a href='../../vaultr/html/vault_client_object.html#method-vault_client_object-help'><code>vaultr::vault_client_object$help()</code></a></span></li>
</ul>
</details>
}}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-new"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-new}{}}}
\subsection{Method \code{new()}}{
Create a \code{vault_client_transit} object. Not typically
called by users.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$new(api_client, mount)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{api_client}}{A \link{vault_api_client} object}

\item{\code{mount}}{Mount point for the backend}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-custom_mount"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-custom_mount}{}}}
\subsection{Method \code{custom_mount()}}{
Set up a \code{vault_client_transit} object at a custom
mount.  For example, suppose you mounted the \code{transit} secret
backend at \verb{/transit2} you might use \code{tr <- vault$secrets$transit$custom_mount("/transit2")} - this
pattern is repeated for other secret and authentication
backends.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$custom_mount(mount)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{mount}}{String, indicating the path that the engine is
mounted at.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_create"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_create}{}}}
\subsection{Method \code{key_create()}}{
Create a new named encryption key of the specified
type. The values set here cannot be changed after key
creation.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_create(
  name,
  key_type = NULL,
  convergent_encryption = NULL,
  derived = NULL,
  exportable = NULL,
  allow_plaintext_backup = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name for the key.  This will be used in all future
interactions with the key - the key itself is not returned.}

\item{\code{key_type}}{Specifies the type of key to create.  The default is
\code{aes256-gcm96}. The currently-supported types are:
\itemize{
\item \code{aes256-gcm96}: AES-256 wrapped with GCM using a 96-bit nonce
size AEAD (symmetric, supports derivation and convergent
encryption)
\item \code{chacha20-poly1305}: ChaCha20-Poly1305 AEAD (symmetric,
supports derivation and convergent encryption)
\item \code{ed25519}: ED25519 (asymmetric, supports derivation). When
using derivation, a sign operation with the same context will
derive the same key and signature; this is a signing analogue
to \code{convergent_encryption}
\item \code{ecdsa-p256}: ECDSA using the P-256 elliptic curve
(asymmetric)
\item \code{rsa-2048}: RSA with bit size of 2048 (asymmetric)
\item \code{rsa-4096}: RSA with bit size of 4096 (asymmetric)
}}

\item{\code{convergent_encryption}}{Logical with default of \code{FALSE}.
If \code{TRUE}, then the key will support convergent encryption,
where the same plaintext creates the same ciphertext. This
requires derived to be set to true. When enabled, each
encryption(/decryption/rewrap/datakey) operation will derive
a \code{nonce} value rather than randomly generate it.}

\item{\code{derived}}{Specifies if key derivation is to be used. If
enabled, all encrypt/decrypt requests to this named key must
provide a context which is used for key derivation (default
is \code{FALSE}).}

\item{\code{exportable}}{Enables keys to be exportable. This allows
for all the valid keys in the key ring to be exported. Once
set, this cannot be disabled (default is \code{FALSE}).}

\item{\code{allow_plaintext_backup}}{If set, enables taking backup of
named key in the plaintext format. Once set, this cannot be
disabled (default is \code{FALSE}).}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_read"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_read}{}}}
\subsection{Method \code{key_read()}}{
Read information about a previously generated key.
The returned object shows the creation time of each key
version; the values are not the keys themselves. Depending on
the type of key, different information may be returned,
e.g. an asymmetric key will return its public key in a
standard format for the type.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_read(name)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{The name of the key to read}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_list"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_list}{}}}
\subsection{Method \code{key_list()}}{
List names of all keys
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_list()}\if{html}{\out{</div>}}
}

}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_delete"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_delete}{}}}
\subsection{Method \code{key_delete()}}{
Delete a key by name.  It will no longer be
possible to decrypt any data encrypted with the named
key. Because this is a potentially catastrophic operation,
the \code{deletion_allowed} tunable must be set using
\verb{$key_update()}.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_delete(name)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{The name of the key to delete.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_update"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_update}{}}}
\subsection{Method \code{key_update()}}{
This method allows tuning configuration values for
a given key. (These values are returned during a read
operation on the named key.)
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_update(
  name,
  min_decryption_version = NULL,
  min_encryption_version = NULL,
  deletion_allowed = NULL,
  exportable = NULL,
  allow_plaintext_backup = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{The name of the key to update}

\item{\code{min_decryption_version}}{Specifies the minimum version of
ciphertext allowed to be decrypted, as an integer (default is
\code{0}). Adjusting this as part of a key rotation policy can
prevent old copies of ciphertext from being decrypted, should
they fall into the wrong hands. For signatures, this value
controls the minimum version of signature that can be
verified against. For HMACs, this controls the minimum
version of a key allowed to be used as the key for
verification.}

\item{\code{min_encryption_version}}{Specifies the minimum version of
the key that can be used to encrypt plaintext, sign payloads,
or generate HMACs, as an integer (default is \code{0}).  Must be 0
(which will use the latest version) or a value greater or
equal to \code{min_decryption_version}.}

\item{\code{deletion_allowed}}{Specifies if the key is allowed to be
deleted, as a logical (default is \code{FALSE}).}

\item{\code{exportable}}{Enables keys to be exportable. This allows
for all the valid keys in the key ring to be exported. Once
set, this cannot be disabled.}

\item{\code{allow_plaintext_backup}}{If set, enables taking backup of
named key in the plaintext format. Once set, this cannot be
disabled.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_rotate"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_rotate}{}}}
\subsection{Method \code{key_rotate()}}{
Rotates the version of the named key. After
rotation, new plaintext requests will be encrypted with the
new version of the key. To upgrade ciphertext to be encrypted
with the latest version of the key, use the rewrap
endpoint. This is only supported with keys that support
encryption and decryption operations.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_rotate(name)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{The name of the key to rotate}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_export"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_export}{}}}
\subsection{Method \code{key_export()}}{
Export the named key. If version is specified, the
specific version will be returned. If latest is provided as
the version, the current key will be provided. Depending on
the type of key, different information may be returned. The
key must be exportable to support this operation and the
version must still be valid.

For more details see
https://github.com/hashicorp/vault/issues/2667 where
HashiCorp says "Part of the "contract" of transit is that the
key is never exposed outside of Vault. We added the ability
to export keys because some enterprises have key escrow
requirements, but it leaves a permanent mark in the key
metadata. I suppose we could at some point allow importing a
key and also leave such a mark."
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_export(name, key_type, version = NULL)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name of the key to export}

\item{\code{key_type}}{Specifies the type of the key to export. Valid
values are \code{encryption-key}, \code{signing-key} and \code{hmac-key}.}

\item{\code{version}}{Specifies the version of the key to read. If
omitted, all versions of the key will be returned. If the
version is set to latest, the current key will be returned}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-data_encrypt"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-data_encrypt}{}}}
\subsection{Method \code{data_encrypt()}}{
This endpoint encrypts the provided plaintext
using the named key.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$data_encrypt(
  key_name,
  data,
  key_version = NULL,
  context = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{key_name}}{Specifies the name of the encryption key to
encrypt against.}

\item{\code{data}}{Data to encrypt, as a raw vector}

\item{\code{key_version}}{Key version to use, as an integer. If not
set, uses the latest version. Must be greater than or equal
to the key's \code{min_encryption_version}, if set.}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-data_decrypt"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-data_decrypt}{}}}
\subsection{Method \code{data_decrypt()}}{
Decrypts the provided ciphertext using the named
key.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$data_decrypt(key_name, data, context = NULL)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{key_name}}{Specifies the name of the encryption key to
decrypt with.}

\item{\code{data}}{The data to decrypt.  Must be a string, as returned
by \verb{$data_encrypt}.}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-data_rewrap"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-data_rewrap}{}}}
\subsection{Method \code{data_rewrap()}}{
Rewraps the provided ciphertext using the latest
version of the named key. Because this never returns
plaintext, it is possible to delegate this functionality to
untrusted users or scripts.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$data_rewrap(
  key_name,
  data,
  key_version = NULL,
  context = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{key_name}}{Specifies the name of the encryption key to
re-encrypt against}

\item{\code{data}}{The data to decrypt.  Must be a string, as returned
by \verb{$data_encrypt}.}

\item{\code{key_version}}{Specifies the version of the key to use for
the operation. If not set, uses the latest version. Must be
greater than or equal to the key's \code{min_encryption_version},
if set.}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-datakey_create"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-datakey_create}{}}}
\subsection{Method \code{datakey_create()}}{
This endpoint generates a new high-entropy key and
the value encrypted with the named key. Optionally return the
plaintext of the key as well.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$datakey_create(
  name,
  plaintext = FALSE,
  bits = NULL,
  context = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Specifies the name of the encryption key to use to
encrypt the datakey}

\item{\code{plaintext}}{Logical, indicating if the plaintext key
should be returned.}

\item{\code{bits}}{Specifies the number of bits in the desired
key. Can be 128, 256, or 512.}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-random"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-random}{}}}
\subsection{Method \code{random()}}{
Generates high-quality random bytes of the
specified length.  This is totally independent of R's random
number stream and provides random numbers suitable for
cryptographic purposes.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$random(bytes = 32, format = "hex")}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{bytes}}{Number of bytes to generate (as an integer)}

\item{\code{format}}{The output format to produce; must be one of
\code{hex} (a single hex string such as \code{d1189e2f83b72ab6}),
\code{base64} (a single base64 encoded string such as
\verb{8TDJekY0mYs=}) or \code{raw} (a raw vector of length \code{bytes}).}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-hash"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-hash}{}}}
\subsection{Method \code{hash()}}{
Generates a cryptographic hash of given data using
the specified algorithm.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$hash(data, algorithm = NULL, format = "hex")}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{data}}{A raw vector of data to hash.  To generate a raw
vector from an R object, one option is to use \code{unserialize(x, NULL)} but be aware that version information may be included.
Alternatively, for a string, one might use \code{charToRaw}.}

\item{\code{algorithm}}{A string indicating the hash algorithm to use.
The exact set of supported algorithms may depend by vault
server version, but as of version 1.0.0 vault supports
\code{sha2-224}, \code{sha2-256}, \code{sha2-384} and \code{sha2-512}.  The
default is \code{sha2-256}.}

\item{\code{format}}{The format of the output - must be one of \code{hex}
or \code{base64}.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-hmac"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-hmac}{}}}
\subsection{Method \code{hmac()}}{
This endpoint returns the digest of given data
using the specified hash algorithm and the named key. The key
can be of any type supported by the \code{transit} engine; the raw
key will be marshalled into bytes to be used for the HMAC
function. If the key is of a type that supports rotation, the
latest (current) version will be used.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$hmac(name, data, key_version = NULL, algorithm = NULL)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Specifies the name of the encryption key to
generate hmac against}

\item{\code{data}}{The input data, as a raw vector}

\item{\code{key_version}}{Specifies the version of the key to use for
the operation. If not set, uses the latest version. Must be
greater than or equal to the key's \code{min_encryption_version},
if set.}

\item{\code{algorithm}}{Specifies the hash algorithm to
use. Currently-supported algorithms are \code{sha2-224},
\code{sha2-256}, \code{sha2-384} and \code{sha2-512}.  The default is
\code{sha2-256}.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-sign"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-sign}{}}}
\subsection{Method \code{sign()}}{
Returns the cryptographic signature of the given
data using the named key and the specified hash
algorithm. The key must be of a type that supports signing.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$sign(
  name,
  data,
  key_version = NULL,
  hash_algorithm = NULL,
  prehashed = FALSE,
  signature_algorithm = NULL,
  context = NULL
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Specifies the name of the encryption key to use for
signing}

\item{\code{data}}{The input data, as a raw vector}

\item{\code{key_version}}{Specifies the version of the key to use for
signing. If not set, uses the latest version. Must be greater
than or equal to the key's \code{min_encryption_version}, if set.}

\item{\code{hash_algorithm}}{Specifies the hash algorithm to
use. Currently-supported algorithms are \code{sha2-224},
\code{sha2-256}, \code{sha2-384} and \code{sha2-512}.  The default is
\code{sha2-256}.}

\item{\code{prehashed}}{Set to true when the input is already
hashed. If the key type is \code{rsa-2048} or \code{rsa-4096}, then the
algorithm used to hash the input should be indicated by the
\code{hash_algorithm} parameter.}

\item{\code{signature_algorithm}}{When using a RSA key, specifies the
RSA signature algorithm to use for signing. Supported
signature types are \code{pss} (the default) and \code{pkcs1v15}.}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-verify_signature"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-verify_signature}{}}}
\subsection{Method \code{verify_signature()}}{
Determine whether the provided signature is valid
for the given data.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$verify_signature(
  name,
  data,
  signature,
  hash_algorithm = NULL,
  signature_algorithm = NULL,
  context = NULL,
  prehashed = FALSE
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name of the key}

\item{\code{data}}{Data to verify, as a raw vector}

\item{\code{signature}}{The signed data, as a string.}

\item{\code{hash_algorithm}}{Specifies the hash algorithm to use. This
can also be specified as part of the URL (see \verb{$sign} and
\verb{$hmac} for details).}

\item{\code{signature_algorithm}}{When using a RSA key, specifies the
RSA signature algorithm to use for signature verification}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}

\item{\code{prehashed}}{Set to \code{TRUE} when the input is already hashed}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-verify_hmac"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-verify_hmac}{}}}
\subsection{Method \code{verify_hmac()}}{
Determine whether the provided signature is valid
for the given data.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$verify_hmac(
  name,
  data,
  signature,
  hash_algorithm = NULL,
  signature_algorithm = NULL,
  context = NULL,
  prehashed = FALSE
)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name of the key}

\item{\code{data}}{Data to verify, as a raw vector}

\item{\code{signature}}{The signed data, as a string.}

\item{\code{hash_algorithm}}{Specifies the hash algorithm to use. This
can also be specified as part of the URL (see \verb{$sign} and
\verb{$hmac} for details).}

\item{\code{signature_algorithm}}{When using a RSA key, specifies the
RSA signature algorithm to use for signature verification}

\item{\code{context}}{Specifies the context for key derivation. This
is required if key derivation is enabled for this key.  Must
be a raw vector.}

\item{\code{prehashed}}{Set to \code{TRUE} when the input is already hashed}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_backup"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_backup}{}}}
\subsection{Method \code{key_backup()}}{
Returns a plaintext backup of a named key. The
backup contains all the configuration data and keys of all
the versions along with the HMAC key. The response from this
endpoint can be used with \verb{$key_restore} to restore the key.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_backup(name)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name of the key to backup}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_restore"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_restore}{}}}
\subsection{Method \code{key_restore()}}{
Restores the backup as a named key. This will
restore the key configurations and all the versions of the
named key along with HMAC keys. The input to this method
should be the output of \verb{$key_restore} method.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_restore(name, backup, force = FALSE)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Name of the restored key.}

\item{\code{backup}}{Backed up key data to be restored. This should be
the output from the \verb{$key_backup} endpoint.}

\item{\code{force}}{Logical.  If \code{TRUE}, then force the restore to
proceed even if a key by this name already exists.}
}
\if{html}{\out{</div>}}
}
}
\if{html}{\out{<hr>}}
\if{html}{\out{<a id="method-vault_client_transit-key_trim"></a>}}
\if{latex}{\out{\hypertarget{method-vault_client_transit-key_trim}{}}}
\subsection{Method \code{key_trim()}}{
This endpoint trims older key versions setting a
minimum version for the keyring. Once trimmed, previous
versions of the key cannot be recovered.
\subsection{Usage}{
\if{html}{\out{<div class="r">}}\preformatted{vault_client_transit$key_trim(name, min_version)}\if{html}{\out{</div>}}
}

\subsection{Arguments}{
\if{html}{\out{<div class="arguments">}}
\describe{
\item{\code{name}}{Key to trim}

\item{\code{min_version}}{The minimum version for the key ring. All
versions before this version will be permanently
deleted. This value can at most be equal to the lesser of
\code{min_decryption_version} and \code{min_encryption_version}. This
is not allowed to be set when either \code{min_encryption_version}
or \code{min_decryption_version} is set to zero.}
}
\if{html}{\out{</div>}}
}
}
}
