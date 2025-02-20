package signing

import (
	"sync"

	"github.com/pkg/errors"
	fssz "github.com/prysmaticlabs/fastssz"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// ForkVersionByteLength length of fork version byte array.
const ForkVersionByteLength = 4

// DomainByteLength length of domain byte array.
const DomainByteLength = 4

// digestMap maps the fork version and genesis validator root to the
// resultant fork digest.
var digestMapLock sync.RWMutex
var digestMap = make(map[string][32]byte)

// ErrSigFailedToVerify returns when a signature of a block object(ie attestation, slashing, exit... etc)
// failed to verify.
var ErrSigFailedToVerify = errors.New("signature did not verify")

// List of descriptions for different kinds of signatures
const (
	// UnknownSignature represents all signatures other than below types
	UnknownSignature string = "unknown signature"
	// BlockSignature represents the block signature from block proposer
	BlockSignature = "block signature"
	// RandaoSignature represents randao specific signature
	RandaoSignature = "randao signature"
	// SelectionProof represents selection proof
	SelectionProof = "selection proof"
	// AggregatorSignature represents aggregator's signature
	AggregatorSignature = "aggregator signature"
	// AttestationSignature represents aggregated attestation signature
	AttestationSignature = "attestation signature"
	// BlsChangeSignature represents signature to BLSToExecutionChange
	BlsChangeSignature = "blschange signature"
	// SyncCommitteeSignature represents sync committee signature
	SyncCommitteeSignature = "sync committee signature"
	// SyncSelectionProof represents sync committee selection proof
	SyncSelectionProof = "sync selection proof"
	// ContributionSignature represents sync committee contributor's signature
	ContributionSignature = "sync committee contribution signature"
	// SyncAggregateSignature represents sync committee aggregator's signature
	SyncAggregateSignature = "sync committee aggregator signature"
)

// ComputeDomainAndSign computes the domain and signing root and sign it using the passed in private key.
func ComputeDomainAndSign(st state.ReadOnlyBeaconState, epoch primitives.Epoch, obj fssz.HashRoot, domain [4]byte, key bls.SecretKey) ([]byte, error) {
	return ComputeDomainAndSignWithoutState(st.Fork(), epoch, domain, st.GenesisValidatorsRoot(), obj, key)
}

// ComputeDomainAndSignWithoutState offers the same functionalit as ComputeDomainAndSign without the need to provide a BeaconState.
// This is particularly helpful for signing values in tests.
func ComputeDomainAndSignWithoutState(fork *ethpb.Fork, epoch primitives.Epoch, domain [4]byte, vr []byte, obj fssz.HashRoot, key bls.SecretKey) ([]byte, error) {
	// EIP-7044: Beginning in Deneb, fix the fork version to Capella for signed exits.
	// This allows for signed validator exits to be valid forever.
	if domain == params.BeaconConfig().DomainVoluntaryExit && epoch >= params.BeaconConfig().DenebForkEpoch {
		fork = &ethpb.Fork{
			PreviousVersion: params.BeaconConfig().CapellaForkVersion,
			CurrentVersion:  params.BeaconConfig().CapellaForkVersion,
			Epoch:           params.BeaconConfig().CapellaForkEpoch,
		}
	}
	d, err := Domain(fork, epoch, domain, vr)
	if err != nil {
		return nil, err
	}
	sr, err := ComputeSigningRoot(obj, d)
	if err != nil {
		return nil, err
	}
	return key.Sign(sr[:]).Marshal(), nil
}

// ComputeSigningRoot computes the root of the object by calculating the hash tree root of the signing data with the given domain.
//
// Spec pseudocode definition:
//
//		def compute_signing_root(ssz_object: SSZObject, domain: Domain) -> Root:
//	   """
//	   Return the signing root for the corresponding signing data.
//	   """
//	   return hash_tree_root(SigningData(
//	       object_root=hash_tree_root(ssz_object),
//	       domain=domain,
//	   ))
func ComputeSigningRoot(object fssz.HashRoot, domain []byte) ([32]byte, error) {
	return Data(object.HashTreeRoot, domain)
}

// Data computes the signing data by utilising the provided root function and then
// returning the signing data of the container object.
func Data(rootFunc func() ([32]byte, error), domain []byte) ([32]byte, error) {
	objRoot, err := rootFunc()
	if err != nil {
		return [32]byte{}, err
	}
	return ComputeSigningRootForRoot(objRoot, domain)
}

// ComputeSigningRootForRoot works the same as ComputeSigningRoot,
// except that gets the root from an argument instead of a callback.
func ComputeSigningRootForRoot(root [32]byte, domain []byte) ([32]byte, error) {
	container := &ethpb.SigningData{
		ObjectRoot: root[:],
		Domain:     domain,
	}
	return container.HashTreeRoot()
}

// ComputeDomainVerifySigningRoot computes domain and verifies signing root of an object given the beacon state, validator index and signature.
func ComputeDomainVerifySigningRoot(st state.ReadOnlyBeaconState, index primitives.ValidatorIndex, epoch primitives.Epoch, obj fssz.HashRoot, domain [4]byte, sig []byte) error {
	v, err := st.ValidatorAtIndex(index)
	if err != nil {
		return err
	}
	d, err := Domain(st.Fork(), epoch, domain, st.GenesisValidatorsRoot())
	if err != nil {
		return err
	}
	return VerifySigningRoot(obj, v.PublicKey, sig, d)
}

// VerifySigningRoot verifies the signing root of an object given its public key, signature and domain.
func VerifySigningRoot(obj fssz.HashRoot, pub, signature, domain []byte) error {
	publicKey, err := bls.PublicKeyFromBytes(pub)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to public key")
	}
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to signature")
	}
	root, err := ComputeSigningRoot(obj, domain)
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}
	if !sig.Verify(publicKey, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// VerifyBlockHeaderSigningRoot verifies the signing root of a block header given its public key, signature and domain.
func VerifyBlockHeaderSigningRoot(blkHdr *ethpb.BeaconBlockHeader, pub, signature, domain []byte) error {
	publicKey, err := bls.PublicKeyFromBytes(pub)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to public key")
	}
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to signature")
	}
	root, err := Data(blkHdr.HashTreeRoot, domain)
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}
	if !sig.Verify(publicKey, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// VerifyBlockSigningRoot verifies the signing root of a block given its public key, signature and domain.
func VerifyBlockSigningRoot(pub, signature, domain []byte, rootFunc func() ([32]byte, error)) error {
	// 주어진 공개키, 서명, 도메인, 루트함수를 이용해서 서명 배치
	set, err := BlockSignatureBatch(pub, signature, domain, rootFunc)
	if err != nil {
		return err
	}
	// fmt.Println("set : ", set)

	// We assume only one signature batch is returned here.
	// 서명 데이터
	sig := set.Signatures[0]
	// 공개키
	publicKey := set.PublicKeys[0]
	// 도메인과 루트함수를 이용해 생성한 서명 루트
	root := set.Messages[0]

	// fmt.Printf("서명 : %x\n", sig)
	// fmt.Printf("공개키 : %x\n", publicKey.Marshal())
	// fmt.Printf("서명 루트 : %x\n", root)

	// 주어진 서명 바이트 배열을 이용해서 BLS 서명 객체를 생성한다.
	rSig, err := bls.SignatureFromBytes(sig)
	if err != nil {
		return err
	}
	// fmt.Printf("rSig : %x\n", rSig)

	if !rSig.Verify(publicKey, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// BlockSignatureBatch retrieves the relevant signature, message and pubkey data from a block and collating it
// into a signature batch object.
func BlockSignatureBatch(pub, signature, domain []byte, rootFunc func() ([32]byte, error)) (*bls.SignatureBatch, error) {
	// 주어진 공개 키 바이트 배열을 이용해서 BLS 공개 키를 생성한다.
	publicKey, err := bls.PublicKeyFromBytes(pub)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert bytes to public key")
	}
	// fmt.Println("pub : ", pub)
	// fmt.Println("publicKey : ", publicKey)

	// utilize custom block hashing function
	// 블록 루트함수와 도메인을 통해 서명 루트를 계산한다.
	root, err := Data(rootFunc, domain)
	if err != nil {
		return nil, errors.Wrap(err, "could not compute signing root")
	}
	// fmt.Printf("서명 루트 : %x\n", root)

	desc := BlockSignature
	return &bls.SignatureBatch{
		Signatures:   [][]byte{signature},
		PublicKeys:   []bls.PublicKey{publicKey},
		Messages:     [][32]byte{root},
		Descriptions: []string{desc},
	}, nil
}

// ComputeDomain returns the domain version for BLS private key to sign and verify with a zeroed 4-byte
// array as the fork version.
// ComputeDomain은 BLS 개인키의 도메인 버전을 반환한다. 포크 버전으로 0인 4바이트 배열으로 서명하고 확인하기 위해
// ## zeroed 4-byte는 배열의 모든 요소가 0으로 초기화된 상태를 의미한다. 이는 기본값으로 사용하기 위함이다.
//
// def compute_domain(domain_type: DomainType, fork_version: Version=None, genesis_validators_root: Root=None) -> Domain:
//
//	"""
//	Return the domain for the ``domain_type`` and ``fork_version``.
//
// 도메인 타입과 포크 버전을 위한 도메인을 반환한다.
//
//	"""
//	if fork_version is None:
//	    fork_version = GENESIS_FORK_VERSION
//	if genesis_validators_root is None:
//	    genesis_validators_root = Root()  # all bytes zero by default
//	fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
//	return Domain(domain_type + fork_data_root[:28])
func ComputeDomain(domainType [DomainByteLength]byte, forkVersion, genesisValidatorsRoot []byte) ([]byte, error) {
	// 포크버전이 nil이면 제네시스 포크버전을 사용한다.
	// 즉 새로운 업데이트가 한번도 적용되지 않은 경우는 제네시스 포크 버전을 사용하겠지
	// 업데이트를 했다는 의미는 특정 에포크 이상에서 새로운 포크 버전 즉 달라진 기능들을 사용한다는 의미이니깐
	if forkVersion == nil {
		forkVersion = params.BeaconConfig().GenesisForkVersion
	}

	// 제네시스 검증자 루트가 nil이면 제네시스 해시를 사용한다.
	// 제네시스 블록에 포함된 검증자들의 루트 해시를 의미한다. 이후의 모든 검증자 루트와는 별개로 초기 상태를 정의한다.
	if genesisValidatorsRoot == nil {
		genesisValidatorsRoot = params.BeaconConfig().ZeroHash[:]
	}
	// fmt.Printf("제네시스 검증자 루트 : %x\n", genesisValidatorsRoot)

	// 포크 데이터 루트를 계산한다.
	// 포크 버전과 제네시스 검증자 루트를 이용해서 포크 데이터 루트를 계산한다.
	var forkBytes [ForkVersionByteLength]byte
	copy(forkBytes[:], forkVersion)
	forkDataRoot, err := computeForkDataRoot(forkBytes[:], genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("포크 데이터 루트 : %x\n", forkDataRoot)

	// 도메인 타입과 포크 데이터 루트를 연결한 것을 반환한다. 도메인 타입은 항상 4바이트이고, 포크 데이터 루트는 28바이트이다.
	return domain(domainType, forkDataRoot[:]), nil
}

// This returns the bls domain given by the domain type and fork data root.
func domain(domainType [DomainByteLength]byte, forkDataRoot []byte) []byte {
	var b []byte
	b = append(b, domainType[:4]...)
	b = append(b, forkDataRoot[:28]...)
	return b
}

// this returns the 32byte fork data root for the “current_version“ and “genesis_validators_root“.
// This is used primarily in signature domains to avoid collisions across forks/chains.
// 현재 버전과 제네시스 검증자 루트를 이용해서 32바이트 포크 데이터 루트를 계산한다.
// 이는 주로 서명 도메인에서 포크/체인 간의 충돌을 피하기 위해 사용된다.
//
// Spec pseudocode definition:
//
//		def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
//	   """
//	   Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
//	   This is used primarily in signature domains to avoid collisions across forks/chains.
//	   """
//	   return hash_tree_root(ForkData(
//	       current_version=current_version,
//	       genesis_validators_root=genesis_validators_root,
//	   ))
func computeForkDataRoot(version, root []byte) ([32]byte, error) {
	// 이미 계산된 포크 데이터 루트가 캐시에 있는지 확인한다.
	digestMapLock.RLock()
	if val, ok := digestMap[string(version)+string(root)]; ok {
		digestMapLock.RUnlock()
		return val, nil
	}
	digestMapLock.RUnlock()

	// 캐시에 없다면 새로 계산한다.
	// 주어진 객체를 해싱해서 32바이트 크기의 해시값으로 반환한다.
	r, err := (&ethpb.ForkData{
		CurrentVersion:        version,
		GenesisValidatorsRoot: root,
	}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, err
	}

	// Cache result of digest computation
	// as this is a hot path and doesn't need
	// to be constantly computed.
	// 이 계산은 포크 데이터 루트를 digestMap에 저장하여 동일한 입력에 대해 빠르게 결과를 반환할 수 있도록 한다.
	// 결과를 캐시에 저장한다.
	digestMapLock.Lock()
	digestMap[string(version)+string(root)] = r
	digestMapLock.Unlock()
	return r, nil
}

// ComputeForkDigest returns the fork for the current version and genesis validators root
//
// Spec pseudocode definition:
//
//		def compute_fork_digest(current_version: Version, genesis_validators_root: Root) -> ForkDigest:
//	   """
//	   Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
//	   This is a digest primarily used for domain separation on the p2p layer.
//	   4-bytes suffices for practical separation of forks/chains.
//	   """
//	   return ForkDigest(compute_fork_data_root(current_version, genesis_validators_root)[:4])
func ComputeForkDigest(version, genesisValidatorsRoot []byte) ([4]byte, error) {
	dataRoot, err := computeForkDataRoot(version, genesisValidatorsRoot)
	if err != nil {
		return [4]byte{}, err
	}
	return bytesutil.ToBytes4(dataRoot[:]), nil
}
