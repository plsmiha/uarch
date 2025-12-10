prefix="3defe7c1"
suffix="a1b"  # mixed lowercase + numbers
full_password="${prefix}${suffix}"
hash=$(echo -n "$full_password" | md5sum | cut -d' ' -f1)
echo "Hash: $hash"
echo "Test: hashcat -m 0 -a 3 target.hash '3defe7c1?1?1?1' -1 ?l?d"
