git diff coniks_server/ | grep ^+ | grep -v ^+++

# Did not really remove any code
# git diff coniks_server/ | grep ^- | grep -v ^---

git diff coniks_test_client/ | grep ^+ | grep -v ^+++

echo
echo "Lines changed: "
echo "Server:"
git diff coniks_server/ | grep ^+ | grep -v ^+++ | wc -l
echo "Test client:"
git diff coniks_test_client/ | grep ^+ | grep -v ^+++ | wc -l
