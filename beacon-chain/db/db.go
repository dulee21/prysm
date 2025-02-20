// Package db defines the ability to create a new database
// for an Ethereum Beacon Node.
package db

import (
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/db/kv"
)

// db.go 파일 설명
// 데이터베이스 관련 기능을 관리하는 역할을 하는 파일이다.
// 데이터베이스와 관련된 기능을 이 폴더에 중앙화 해 유지보수성을 높인다.
// 데이터베이스의 생성 및 경로 설정로직을 쉽게 변경할 수 있게 설계되어 다른 모듈이나 패키지로 대체할 수 있다.

//// 데이터를 저장할 때 db 객체와 kv 객체를 사용하는 것 같다.
//// 둘의 차이는 무엇인가?
// 이 함수는 데이터가 저장될 파일 경로를 생성한다.
// kv.StoreDatafilePath와 같이 다른 함수를 호출해 경로를 생성한다.
// 이렇게 작성한 이유는 데이터베이스 파일을 저장할 때 경로를 생성하는 로직이 변경될 수 있기 때문이다.
// 만약 kv.StoreDatafilePath가 변경되면 NewFileName에서 다른 모듈(다른 db 패키지)로 교체하기만 하면 된다.
// 이렇게 작성하면 모듈 간의 의존성을 줄일 수 있다.

// NewFileName uses the KVStoreDatafilePath so that if this layer of
// indirection between db.NewDB->kv.NewKVStore ever changes, it will be easy to remember
// to also change this filename indirection at the same time.
// NewFileName은 KVStoreDatafilePath를 사용하여 db.NewDB->kv.NewKVStore 간의
// 간접 계층이 변경될 경우 이 파일 이름 간접 참조도 동시에 변경해야 한다는 것을
// 쉽게 기억할 수 있도록 합니다.
func NewFileName(dirPath string) string {
	return kv.StoreDatafilePath(dirPath)
}
