TM_VERSION := 0.13.0
TM_SHA256SUM := 36d773d4c2890addc61cc87a72c1e9c21c89516921b0defb0edfebde719b4b85

prep: authorize.stamp connect

stop: | connect
	./cmd.sh killall tendermint ekiden-consensus

clear: | install-tendermint.stamp connect
	./cmd.sh ./tendermint unsafe_reset_all

genesis.stamp: genesis.json | install-tendermint.stamp connect
	./upload_validator_keys.sh $(TM_VERSION)
	touch $@

genesis.json:
	./create_validator_keys.sh $(TM_VERSION)

install-consensus.stamp: ../../target/release/ekiden-consensus | connect
	./send.sh $<
	touch $@

install-tendermint.stamp: tendermint | connect
	./send.sh $<
	./cmd.sh mkdir .tendermint
	touch $@

connect: known_hosts ssh_config

tendermint: tendermint_$(TM_VERSION)_linux_amd64.zip
	unzip $<
	touch $@ # mark as fresh

tendermint_$(TM_VERSION)_linux_amd64.zip:
	wget https://s3-us-west-2.amazonaws.com/tendermint/binaries/tendermint/v$(TM_VERSION)/$@
	echo "$(TM_SHA256SUM)  $@" | sha256sum -c

ssh_config: create_ssh_config.sh ips.txt
	./$<

known_hosts: create_known_hosts.sh ips.txt
	./$<

authorize.stamp: authorize_security_groups.sh ips.txt
	./$<
	touch $@

ips.txt: get_ips.sh launch.stamp
	./$< >ips-tmp.txt
	mv ips-tmp.txt $@

.PHONY: prep connect
