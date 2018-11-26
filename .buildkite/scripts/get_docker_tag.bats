#!/usr/bin/env bats

##
# Test file for get-docker-tags.sh
#
# If you are not familiar, check out
# Bash Automated Testing System (BATS):
# https://github.com/bats-core/bats-core
##

@test "Provide zero arguments should error" {
  run ./get-docker-tag.sh
  [ "$status" -eq 1 ]
  [[ "$output" =~ "\$1: unbound variable" ]]
}

@test "Provide only git_branch should error" {
  run ./get-docker-tag.sh 'some_git_branch_name'
  [ "$status" -eq 1 ]
  [[ "$output" =~ "\$2: unbound variable" ]]
}

@test "Provide git_branch, git_commit_sha, and git_tag_name should succeed" {
  run ./get-docker-tag.sh 'some_git_branch_name' 'some_git_commit_sha' 'some_git_tag_name'
  [ "$status" -eq 0 ]
}

@test "Provide branch(master) and tag: should use tag as prefix" {
  run ./get-docker-tag.sh 'master' 'some_sha' 'some_tag_name'
  [ "$status" -eq 0 ]
  [[ "$output" =~ "some_tag_name-" ]]
}

@test "Provide branch(master) and no tag: should use master as prefix" {
  run ./get-docker-tag.sh 'master' 'some_sha'
  [ "$status" -eq 0 ]
  [[ "$output" =~ "master-" ]]
}

@test "Provide branch(non-master) and no tag: should use commit_sha" {
  run ./get-docker-tag.sh 'non_master_branch' 'some_sha'
  [ "$status" -eq 0 ]
  [ "$output" = "some_sha" ]
}
