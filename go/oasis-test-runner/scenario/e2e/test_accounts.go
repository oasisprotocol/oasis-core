package e2e

import stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests/debug"

// The people that made all the test staking genesis documents neglected
// to really add comments where these accounts came from.  Presumably they
// are deterministically generated identities of various things.  Someone
// can go back and derive these at a later date.
//
// Ordering of the mystery accounts replicates what was in the txsource
// and gas fees JSON documents.
//
// WARNING: Adding more MysteryAccounts is cause for immediate rejection
// of future proposed changes.  This list should shrink, not grow.
var (
	EntityAccount = stakingTests.AddressFromString("oasis1qq7us2p22udg2t24u6ry4m29wzql005pjsske8gt")
	LockupAccount = stakingTests.AddressFromString("oasis1qpt202cf6t0s5ugkk34p83yf0c30gpjkny92u7dh")

	MysteryAccount0 = stakingTests.AddressFromString("oasis1qryg8qf3ydzcphr328l8psz007fms9dxeuy8lgzq")
	MysteryAccount1 = stakingTests.AddressFromString("oasis1qz74khszg55gfnmpxut3t3gdymn76hfchu9nhtd0")
	MysteryAccount8 = stakingTests.AddressFromString("oasis1qqkspsglt3quhpkghr837trfwm048srjuv8g92jj")

	MysteryAccount2 = stakingTests.AddressFromString("oasis1qp6tl30ljsrrqnw2awxxu2mtxk0qxyy2nymtsy90")
	MysteryAccount3 = stakingTests.AddressFromString("oasis1qr77y0cqdzcqgz2wqkv59yz0j4vfvyryfv8vxllt")
	MysteryAccount4 = stakingTests.AddressFromString("oasis1qzyw75ds6nw0af98xfmmpl3z8sgf3mdslvtzzcn6")
	MysteryAccount9 = stakingTests.AddressFromString("oasis1qrp7l53vn6h2z7p242ldtkqtttz2jf9dwsgu05aa")

	MysteryAccount5 = stakingTests.AddressFromString("oasis1qrhp36j49ncpaac0aufwyuvtk04nfxcj2yq7y4my")
	MysteryAccount6 = stakingTests.AddressFromString("oasis1qzc2fexm30puzq2cmlm832fvpnyaxrq33cx4zukj")

	MysteryAccount7  = stakingTests.AddressFromString("oasis1qpx0k28va6n0r25qd2j4jdh9f42n5vex6s9lp780")
	MysteryAccount10 = stakingTests.AddressFromString("oasis1qz30d8mqzrsrsu7fr0e6nxk0ze7ffdkj8ur7sqp0")
)
