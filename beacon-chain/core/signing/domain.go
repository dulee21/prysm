package signing

import (
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	eth "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// Domain returns the domain version for BLS private key to sign and verify.

// Spec pseudocode definition:
//
//	def get_domain(state: BeaconState, domain_type: DomainType, epoch: Epoch=None) -> Domain:
//	  """
//	  Return the signature domain (fork version concatenated with domain type) of a message.
//	  메세지의 서명 도메인 (도메인 타입과 포크 버전을 연결한 것)을 반환한다.
//	  """
//	  epoch = get_current_epoch(state) if epoch is None else epoch
//	  fork_version = state.fork.previous_version if epoch < state.fork.epoch else state.fork.current_version
//	  return compute_domain(domain_type, fork_version, state.genesis_validators_root)
func Domain(fork *eth.Fork, epoch primitives.Epoch, domainType [bls.DomainByteLength]byte, genesisRoot []byte) ([]byte, error) {
	// 현재 포크 정보를 확인한다.
	if fork == nil {
		return []byte{}, errors.New("nil fork or domain type")
	}
	var forkVersion []byte
	// fmt.Println("포크 에포크 : ", fork.Epoch)

	// 에포크가 포크 에포크보다 작으면 이전 버전을, 그렇지 않으면 현재 버전을 선택한다.
	// 아 즉 특정 에포크 이전엔 업데이트 되지 않은 방식을 사용하는거고, 그 이후에 업데이트된 방식을 사용하는것
	// 여기서 epoch는 현재 슬롯 번호로 계산된 에포크 번호
	// fork.Epoch는 새로운 포크가 적용되는 에포크 번호를 말하는 것
	// 그래서 로그에는 항상 fork.Epoch가 0이다, 왜냐하면 새로운 포크를 적용하지 않았으니
	if epoch < fork.Epoch {
		forkVersion = fork.PreviousVersion
	} else {
		forkVersion = fork.CurrentVersion
	}

	// 선택한 포크 버전의 길이가 4바이트인지 확인한다.
	if len(forkVersion) != 4 {
		return []byte{}, errors.New("fork version length is not 4 byte")
	}

	// fmt.Printf("포크 버전 : %x\n", forkVersion)

	// 선택한 포크 버전을 4바이트 배열로 복사한다.
	var forkVersionArray [4]byte
	copy(forkVersionArray[:], forkVersion[:4])
	return ComputeDomain(domainType, forkVersionArray[:], genesisRoot)
}
