##' @section Methods:
##'
##' \describe{
##' \item{\code{key_status}}{
##'   Return information about the current encryption key of Vault.
##'   \cr\emph{Usage:}\preformatted{key_status()}
##' }
##' \item{\code{is_initialized}}{
##'   Returns the initialization status of Vault
##'   \cr\emph{Usage:}\preformatted{is_initialized()}
##' }
##' \item{\code{init}}{
##'   This endpoint initializes a new Vault. The Vault must not have been previously initialized.
##'   \cr\emph{Usage:}\preformatted{init(secret_shares, secret_threshold)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{secret_shares}:   Integer, specifying the number of shares to split the master key into
##'     }
##'
##'     \item{\code{secret_threshold}:   Integer, specifying the number of shares required to reconstruct the master key. This must be less than or equal secret_shares
##'     }
##'   }
##' }
##' \item{\code{leader_status}}{
##'   Check the high availability status and current leader of Vault
##'   \cr\emph{Usage:}\preformatted{leader_status()}
##' }
##' \item{\code{rekey_status}}{
##'   Reads the configuration and progress of the current rekey attempt
##'   \cr\emph{Usage:}\preformatted{rekey_status()}
##' }
##' \item{\code{rekey_start}}{
##'   This method begins a new rekey attempt. Only a single rekey attempt can take place at a time, and changing the parameters of a rekey requires cancelling and starting a new rekey, which will also provide a new nonce.
##'   \cr\emph{Usage:}\preformatted{rekey_start(secret_shares, secret_threshold)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{secret_shares}:   Integer, specifying the number of shares to split the master key into
##'     }
##'
##'     \item{\code{secret_threshold}:   Integer, specifying the number of shares required to reconstruct the master key. This must be less than or equal secret_shares
##'     }
##'   }
##' }
##' \item{\code{rekey_cancel}}{
##'   This method cancels any in-progress rekey. This clears the rekey settings as well as any progress made. This must be called to change the parameters of the rekey. Note: verification is still a part of a rekey. If rekeying is cancelled during the verification flow, the current unseal keys remain valid.
##'   \cr\emph{Usage:}\preformatted{rekey_cancel()}
##' }
##' \item{\code{rekey_submit}}{
##'   This method is used to enter a single master key share to progress the rekey of the Vault. If the threshold number of master key shares is reached, Vault will complete the rekey. Otherwise, this method must be called multiple times until that threshold is met. The rekey nonce operation must be provided with each call.
##'   \cr\emph{Usage:}\preformatted{rekey_submit(key, nonce)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{key}:   Specifies a single master share key (a string)
##'     }
##'
##'     \item{\code{nonce}:   Specifies the nonce of the rekey operation (a string)
##'     }
##'   }
##' }
##' \item{\code{rotate}}{
##'   This method triggers a rotation of the backend encryption key. This is the key that is used to encrypt data written to the storage backend, and is not provided to operators. This operation is done online. Future values are encrypted with the new key, while old values are decrypted with previous encryption keys.
##'   \cr\emph{Usage:}\preformatted{rotate()}
##' }
##' \item{\code{seal}}{
##'   Seal the vault, preventing any access to it.  After the vault is sealed, it must be unsealed for further use.
##'   \cr\emph{Usage:}\preformatted{seal()}
##' }
##' \item{\code{seal_status}}{
##'   Check the seal status of a Vault.  This method can be used even when the client is not authenticated with the vault (which will the case for a sealed vault).
##'   \cr\emph{Usage:}\preformatted{seal_status()}
##' }
##' \item{\code{unseal}}{
##'   Submit a portion of a key to unseal the vault.  This method is typically called by multiple different operators to assemble the master key.
##'   \cr\emph{Usage:}\preformatted{unseal(key, reset = FALSE)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{key}:   The master key share
##'     }
##'
##'     \item{\code{reset}:   Logical, indicating if the unseal process should start be started again.
##'     }
##'   }
##' }
##' }
