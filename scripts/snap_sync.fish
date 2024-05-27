#!/usr/bin/env fish

set node $argv[1]

set folder 'schnorr_fhe'

echo "Syncing to $node.stanford.edu:/lfs/local/0/kzliu/$folder"

# Copy root dir's python files and select folders
scp -r src tests stash scripts README.md \
    kzliu@$node.stanford.edu:/lfs/local/0/kzliu/$folder
