package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
//	"github.com/perkeep/perkeep/third_party/code.google.com/p/go.crypto/openpgp"
//	"github.com/perkeep/perkeep/third_party/code.google.com/p/go.crypto/openpgp" "v0.0.0-20140806175519-2f1a4f06cb96"
//	"github.com/perkeep/perkeep@v0.0.0-20140806175519-2f1a4f06cb96/third_party/code.google.com/p/go.crypto/openpgp"
//	"golang.org/x/crypto/openpgp"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Read armored private key into type EntityList
	// An EntityList contains one or more Entities.
	// This assumes there is only one Entity involved
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	if err != nil {
		log.Fatal(err)
	}
	entity := entitylist[0]
	fmt.Println("Private key from armored string:", entity.Identities)

	// Decrypt private key using passphrase
	passphrase := []byte("golang")
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		fmt.Println("Decrypting private key using passphrase")
		err := entity.PrivateKey.Decrypt(passphrase)
		if err != nil {
			fmt.Println("failed to decrypt key")
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(passphrase)
			if err != nil {
				fmt.Println("failed to decrypt subkey")
			}
		}
	}

	// Decrypt base64 encoded encrypted message using decrypted private key
	dec, err := base64.StdEncoding.DecodeString(base64EncryptedMessage)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entitylist, nil /* no prompt */, nil)
	if err != nil {
		fmt.Println("error reading message", err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	fmt.Println("md:", string(bytes))

}

// pub   1024R/7F98BBCE 2014-01-04
// uid                  Golang Test (Private key password is 'golang') <golangtest@test.com>
// sub   1024R/5F34A320 2014-01-04
const privateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1
 
lQH+BFLHbYYBBADCjgKHmPmwBxI3c3DPVoSdu0+EJl/EsS2HEaN63dnLkGsMAs+4
32wsywmMrzKqCL40sbhJVYBcfe0chL+cry4O54DX7+gA0ZSVzFUN2EGocnkaHzyS
fuUtBdCTmoWZZAGFiBwlIS7aE/86SOyHksFo8LRC9W/GIWQS2PbcadvUywARAQAB
/gMDApJxOwcsfChBYCCmhOAvotKdYcy7nuG7dyGDBlpclLJtH/PaakKSE33NtEj4
1fyixQOdwApxvuQ2P0VX3pie/De1KpbeqXfnPLsmsXQwrRPOo38T5zeJ5ToWUGDC
Oia69ep3kmHbAW41EBH/uk/nMM91QUdl4mkYsc3dhVOXbmf0xyRoP/Afqha4UhdZ
0XKlIZP1a5+3NF/Q6dAVG0+FlO5Hcai8n98jW0id8Yf6zI+1gFGvYYKhlifkdJeK
Nf4YEvOXALEvaQqkcJOxEca+BmqsgCIFctJe9Bahx97Ep5hP7AH0aBmtZfmGmZwB
GYoevUtKa4ASVmK8RaddBvIjcrWsoAsYMpDGYaE0fcdtxsBf3uT1Q8IMsT+ZRjjV
TfvJ8aW14ZrLI98KdtXaOPZs91mML+3iw1c/1O/IEJfwxrUni2p/fDmCYU9eHR3u
Q0PwVR0MCUHI1fGuUoetW2gYIxfklvBtEFWW1BD6fCpCtERHb2xhbmcgVGVzdCAo
UHJpdmF0ZSBrZXkgcGFzc3dvcmQgaXMgJ2dvbGFuZycpIDxnb2xhbmd0ZXN0QHRl
c3QuY29tPoi4BBMBAgAiBQJSx22GAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIX
gAAKCRBVSiCHf5i7zqKJA/sFUM2TfL2VZKWC7E1N1wwZctB9Bf77SeAPSVpGCZ0c
iUYIFdwwGowKtjoDrsbYgPp+UGOyYMD6tGzWKaJrQQoDyaQqVVRhbNXB7Jz7JT2a
qKHD1t7cx5FfUzDMBNou3TOWHomDXyQGDAULAZnjaOj8/pDe6poxyBluSjMJUzfD
pp0B/gRSx22GAQQArUMDqkGng9Cppk73UBWBd7jhhbtk0eaRQh/goUHhKJerZ4LM
Q21IKyIX+GQbscDpccpXMI6eThXxrL+D8G4cNb4ewvT0zc20+T91ztgT9A/4Vifc
EPQCErTqY/oZphAzZM1p6sRenc22e42iT0Iibd5gCs2wnSNeUzybDcuQi2EAEQEA
Af4DAwKScTsHLHwoQWCYayWqio8purPTonYogZSN3QwaheS2Y0NE7skdLOvP97vi
Rh7BktS6Dkgu0T3D39+q0O6ZO7XErvTVoas1F0HXzId4tiIicmx4tYNyWI4NrSO7
6TQPz/bQe8ZN+plG5cgZowts6g6RSfQxoW21LrP8Lh+OEdcYwWf7BTukAYmD3oq9
RxdfYI7hnbVGFdOqQUQNcxZkbdrsF9ITjQb/KRln5/99E1Kp1D45VpPOs7NT3orA
mnfSslJXVNm1uK6FDBX2iUe3JaAmgh+RLGXQXRZKJW4DGDTyYdwR4hO8cYix2+8z
+XuwdVDPKBnzKn190m6xpdLyvKfj1BQhX14NShPQZ3QJiMU0k4Js23XSsWs9NSxI
FjjE9/mOFVUH25KN+X7rzBPo2S0pMQLqyQxSLIdI2LPDxzlknctT6OoBPKPJjb7S
Lt5GhIA5Cz+cohfX6LePG4FkvwU32tTRBz5YNhFBizmS+YifBBgBAgAJBQJSx22G
AhsMAAoJEFVKIId/mLvOulED/2uUh/qjOT468XoK6Xt837w45JQPpLqiGH9KJgqF
rUxJMw1bIE2G606OY6hCgeE+YC8qny29hQtXhKIquUI/0A1qK3aCZhwqyqT+QjvF
6Xi0i/HrgQwCyBopY3uGndMbvthxU0KO0d6seMZltHDr8YaU1JvDwNFDQVuw+Rqy
57ET
=nvLl
-----END PGP PRIVATE KEY BLOCK-----`

// Encrypted by public key message for
// pub   1024R/7F98BBCE 2014-01-04
// uid                  Golang Test (Private key password is 'golang') <golangtest@test.com>
// echo -n "Test base64 GPG public key encrypted string" | gpg -er 7F98BBCE | base64
const base64EncryptedMessage = `hIwDBZMeL180oyABA/96IfZ30BGsXIUD2Wul/vgWSFY/1fhVZAbpuoqLCZdXiYfnR3nXejmJb3kW5fKM+FsDku4T0p+Ax+hBZSfA51qzX8kECh04ASZpUIcaFQ+lpw8b6DjZf3EaTNqyWymqEAaupWUIm9U+K64GzzJlxtgEqxKGywLzajDuY5l+y0t+UdJmAVKZsJU8jM7HXgvv3CwT67mmFmbrjKATragcgDJ8lcyHObT2HAFLAWXqKIO3WaZwrNCMVaOdj0LUcpVk1/ho1lNqbmdbjgwnnT4e5bPl3JVUHjUuRnCDg0vdsRptHv+AOTQi2l9I`
