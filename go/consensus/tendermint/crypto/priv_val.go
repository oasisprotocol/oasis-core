// Tendermint Go-Common
// Copyright (C) 2015 Tendermint
//
//
//
//                                  Apache License
//                            Version 2.0, January 2004
//                         https://www.apache.org/licenses/
//
//    TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
//
//    1. Definitions.
//
//       "License" shall mean the terms and conditions for use, reproduction,
//       and distribution as defined by Sections 1 through 9 of this document.
//
//       "Licensor" shall mean the copyright owner or entity authorized by
//       the copyright owner that is granting the License.
//
//       "Legal Entity" shall mean the union of the acting entity and all
//       other entities that control, are controlled by, or are under common
//       control with that entity. For the purposes of this definition,
//       "control" means (i) the power, direct or indirect, to cause the
//       direction or management of such entity, whether by contract or
//       otherwise, or (ii) ownership of fifty percent (50%) or more of the
//       outstanding shares, or (iii) beneficial ownership of such entity.
//
//       "You" (or "Your") shall mean an individual or Legal Entity
//       exercising permissions granted by this License.
//
//       "Source" form shall mean the preferred form for making modifications,
//       including but not limited to software source code, documentation
//       source, and configuration files.
//
//       "Object" form shall mean any form resulting from mechanical
//       transformation or translation of a Source form, including but
//       not limited to compiled object code, generated documentation,
//       and conversions to other media types.
//
//       "Work" shall mean the work of authorship, whether in Source or
//       Object form, made available under the License, as indicated by a
//       copyright notice that is included in or attached to the work
//       (an example is provided in the Appendix below).
//
//       "Derivative Works" shall mean any work, whether in Source or Object
//       form, that is based on (or derived from) the Work and for which the
//       editorial revisions, annotations, elaborations, or other modifications
//       represent, as a whole, an original work of authorship. For the purposes
//       of this License, Derivative Works shall not include works that remain
//       separable from, or merely link (or bind by name) to the interfaces of,
//       the Work and Derivative Works thereof.
//
//       "Contribution" shall mean any work of authorship, including
//       the original version of the Work and any modifications or additions
//       to that Work or Derivative Works thereof, that is intentionally
//       submitted to Licensor for inclusion in the Work by the copyright owner
//       or by an individual or Legal Entity authorized to submit on behalf of
//       the copyright owner. For the purposes of this definition, "submitted"
//       means any form of electronic, verbal, or written communication sent
//       to the Licensor or its representatives, including but not limited to
//       communication on electronic mailing lists, source code control systems,
//       and issue tracking systems that are managed by, or on behalf of, the
//       Licensor for the purpose of discussing and improving the Work, but
//       excluding communication that is conspicuously marked or otherwise
//       designated in writing by the copyright owner as "Not a Contribution."
//
//       "Contributor" shall mean Licensor and any individual or Legal Entity
//       on behalf of whom a Contribution has been received by Licensor and
//       subsequently incorporated within the Work.
//
//    2. Grant of Copyright License. Subject to the terms and conditions of
//       this License, each Contributor hereby grants to You a perpetual,
//       worldwide, non-exclusive, no-charge, royalty-free, irrevocable
//       copyright license to reproduce, prepare Derivative Works of,
//       publicly display, publicly perform, sublicense, and distribute the
//       Work and such Derivative Works in Source or Object form.
//
//    3. Grant of Patent License. Subject to the terms and conditions of
//       this License, each Contributor hereby grants to You a perpetual,
//       worldwide, non-exclusive, no-charge, royalty-free, irrevocable
//       (except as stated in this section) patent license to make, have made,
//       use, offer to sell, sell, import, and otherwise transfer the Work,
//       where such license applies only to those patent claims licensable
//       by such Contributor that are necessarily infringed by their
//       Contribution(s) alone or by combination of their Contribution(s)
//       with the Work to which such Contribution(s) was submitted. If You
//       institute patent litigation against any entity (including a
//       cross-claim or counterclaim in a lawsuit) alleging that the Work
//       or a Contribution incorporated within the Work constitutes direct
//       or contributory patent infringement, then any patent licenses
//       granted to You under this License for that Work shall terminate
//       as of the date such litigation is filed.
//
//    4. Redistribution. You may reproduce and distribute copies of the
//       Work or Derivative Works thereof in any medium, with or without
//       modifications, and in Source or Object form, provided that You
//       meet the following conditions:
//
//       (a) You must give any other recipients of the Work or
//           Derivative Works a copy of this License; and
//
//       (b) You must cause any modified files to carry prominent notices
//           stating that You changed the files; and
//
//       (c) You must retain, in the Source form of any Derivative Works
//           that You distribute, all copyright, patent, trademark, and
//           attribution notices from the Source form of the Work,
//           excluding those notices that do not pertain to any part of
//           the Derivative Works; and
//
//       (d) If the Work includes a "NOTICE" text file as part of its
//           distribution, then any Derivative Works that You distribute must
//           include a readable copy of the attribution notices contained
//           within such NOTICE file, excluding those notices that do not
//           pertain to any part of the Derivative Works, in at least one
//           of the following places: within a NOTICE text file distributed
//           as part of the Derivative Works; within the Source form or
//           documentation, if provided along with the Derivative Works; or,
//           within a display generated by the Derivative Works, if and
//           wherever such third-party notices normally appear. The contents
//           of the NOTICE file are for informational purposes only and
//           do not modify the License. You may add Your own attribution
//           notices within Derivative Works that You distribute, alongside
//           or as an addendum to the NOTICE text from the Work, provided
//           that such additional attribution notices cannot be construed
//           as modifying the License.
//
//       You may add Your own copyright statement to Your modifications and
//       may provide additional or different license terms and conditions
//       for use, reproduction, or distribution of Your modifications, or
//       for any such Derivative Works as a whole, provided Your use,
//       reproduction, and distribution of the Work otherwise complies with
//       the conditions stated in this License.
//
//    5. Submission of Contributions. Unless You explicitly state otherwise,
//       any Contribution intentionally submitted for inclusion in the Work
//       by You to the Licensor shall be under the terms and conditions of
//       this License, without any additional terms or conditions.
//       Notwithstanding the above, nothing herein shall supersede or modify
//       the terms of any separate license agreement you may have executed
//       with Licensor regarding such Contributions.
//
//    6. Trademarks. This License does not grant permission to use the trade
//       names, trademarks, service marks, or product names of the Licensor,
//       except as required for reasonable and customary use in describing the
//       origin of the Work and reproducing the content of the NOTICE file.
//
//    7. Disclaimer of Warranty. Unless required by applicable law or
//       agreed to in writing, Licensor provides the Work (and each
//       Contributor provides its Contributions) on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
//       implied, including, without limitation, any warranties or conditions
//       of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
//       PARTICULAR PURPOSE. You are solely responsible for determining the
//       appropriateness of using or redistributing the Work and assume any
//       risks associated with Your exercise of permissions under this License.
//
//    8. Limitation of Liability. In no event and under no legal theory,
//       whether in tort (including negligence), contract, or otherwise,
//       unless required by applicable law (such as deliberate and grossly
//       negligent acts) or agreed to in writing, shall any Contributor be
//       liable to You for damages, including any direct, indirect, special,
//       incidental, or consequential damages of any character arising as a
//       result of this License or out of the use or inability to use the
//       Work (including but not limited to damages for loss of goodwill,
//       work stoppage, computer failure or malfunction, or any and all
//       other commercial damages or losses), even if such Contributor
//       has been advised of the possibility of such damages.
//
//    9. Accepting Warranty or Additional Liability. While redistributing
//       the Work or Derivative Works thereof, You may choose to offer,
//       and charge a fee for, acceptance of support, warranty, indemnity,
//       or other liability obligations and/or rights consistent with this
//       License. However, in accepting such obligations, You may act only
//       on Your own behalf and on Your sole responsibility, not on behalf
//       of any other Contributor, and only if You agree to indemnify,
//       defend, and hold each Contributor harmless for any liability
//       incurred by, or claims asserted against, such Contributor by reason
//       of your accepting any such warranty or additional liability.
//
//    END OF TERMS AND CONDITIONS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        https://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	_ "unsafe" // For go:linkname.

	tmcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"
	tminternal "github.com/tendermint/tendermint/uninternal"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// This derives heavily from `tendermint/privval/file.go` for reasons that should
// be obvious, and is probably covered by the Tendermint (Apache 2) license.
//
// Frustratingly, while it should be possible to reuse most of the FilePV
// implementation, all of the useful helpers are not exported, and neither is
// `FilePVLastSignState.filePath`.

//go:linkname checkVotesOnlyDifferByTimestamp github.com/tendermint/tendermint/privval.checkVotesOnlyDifferByTimestamp
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool)

//go:linkname checkProposalsOnlyDifferByTimestamp github.com/tendermint/tendermint/privval.checkProposalsOnlyDifferByTimestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool)

const privValFileName = "oasis_priv_validator.json"

const (
	// stepNone      int8 = 0
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

func voteToStep(vote *tmproto.Vote) int8 {
	switch vote.Type {
	case tmproto.PrevoteType:
		return stepPrevote
	case tmproto.PrecommitType:
		return stepPrecommit
	default:
		panic(fmt.Sprintf("Unknown vote type: %v", vote.Type))
	}
}

type privVal struct {
	privval.FilePVLastSignState
	PublicKey signature.PublicKey `json:"public_key"`

	filePath string
	signer   signature.Signer
}

func (pv *privVal) GetPubKey(ctx context.Context) (tmcrypto.PubKey, error) {
	return PublicKeyToTendermint(&pv.PublicKey), nil
}

func (pv *privVal) SignVote(ctx context.Context, chainID string, vote *tmproto.Vote) error {
	height, round, step := vote.Height, vote.Round, voteToStep(vote)

	equivocation, err := pv.CheckHRS(height, round, step)
	if err != nil {
		return fmt.Errorf("tendermint/crypto: failed to check vote H/R/S: %w", err)
	}

	signBytes := tmtypes.VoteSignBytes(chainID, vote)
	if equivocation {
		if bytes.Equal(signBytes, pv.SignBytes) {
			vote.Signature = pv.Signature
		} else if ts, ok := checkVotesOnlyDifferByTimestamp(pv.SignBytes, signBytes); ok {
			vote.Timestamp = ts
			vote.Signature = pv.Signature
		} else {
			err = fmt.Errorf("tendermint/crypto: conflicting vote")
		}
		return err
	}

	sig, err := pv.signer.ContextSign(tendermintSignatureContext, signBytes)
	if err != nil {
		return fmt.Errorf("tendermint/crypto: failed to sign vote: %w", err)
	}
	if err = pv.update(height, round, step, signBytes, sig); err != nil {
		return err
	}
	vote.Signature = sig

	return nil
}

func (pv *privVal) SignProposal(ctx context.Context, chainID string, proposal *tmproto.Proposal) error {
	height, round, step := proposal.Height, proposal.Round, stepPropose

	equivocation, err := pv.CheckHRS(height, round, step)
	if err != nil {
		return fmt.Errorf("tendermint/crypto: failed to check proposal H/R/S: %w", err)
	}

	signBytes := tmtypes.ProposalSignBytes(chainID, proposal)
	if equivocation {
		if bytes.Equal(signBytes, pv.SignBytes) {
			proposal.Signature = pv.Signature
		} else if ts, ok := checkProposalsOnlyDifferByTimestamp(pv.SignBytes, signBytes); ok {
			proposal.Timestamp = ts
			proposal.Signature = pv.Signature
		} else {
			err = fmt.Errorf("tendermint/crypto: conflicting proposal")
		}
		return err
	}

	sig, err := pv.signer.ContextSign(tendermintSignatureContext, signBytes)
	if err != nil {
		return fmt.Errorf("tendermint/crypto: failed to sign proposal: %w", err)
	}
	if err = pv.update(height, round, step, signBytes, sig); err != nil {
		return err
	}
	proposal.Signature = sig

	return nil
}

func (pv *privVal) update(height int64, round int32, step int8, signBytes, sig []byte) error {
	pv.Height = height
	pv.Round = round
	pv.Step = step
	pv.SignBytes = signBytes
	pv.Signature = sig
	return pv.save()
}

func (pv *privVal) save() error {
	b, err := json.Marshal(pv)
	if err != nil {
		return err
	}
	if err = tminternal.WriteFileAtomic(pv.filePath, b, 0o600); err != nil {
		return fmt.Errorf("tendermint/crypto: failed to save private validator file: %w", err)
	}

	return nil
}

// LoadOrGeneratePrivVal loads or generates a tendermint PrivValidator for an
// Oasis node signature signer.
func LoadOrGeneratePrivVal(baseDir string, signer signature.Signer) (tmtypes.PrivValidator, error) {
	fn := filepath.Join(baseDir, privValFileName)

	pv := &privVal{
		filePath: fn,
		signer:   signer,
	}

	b, err := ioutil.ReadFile(fn)
	if err == nil {
		if err = json.Unmarshal(b, &pv); err != nil {
			return nil, fmt.Errorf("tendermint/crypto: failed to parse private validator file: %w", err)
		}

		// Tendermint doesn't do this, but it's cheap insurance.
		if !signer.Public().Equal(pv.PublicKey) {
			return nil, fmt.Errorf("tendermint/crypto: public key mismatch, state corruption?: %w", err)
		}
	} else if os.IsNotExist(err) {
		pv.PublicKey = signer.Public()

		if err = pv.save(); err != nil {
			return nil, fmt.Errorf("tendermint/crypto: failed to save newly generate key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("tendermint/crypto: failed to load private validator file: %w", err)
	}

	return pv, nil
}
