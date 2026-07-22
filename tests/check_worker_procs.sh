for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  name=$(cat /proc/$pid/status 2>/dev/null | grep '^Name:' | cut -f2)
  state=$(cat /proc/$pid/status 2>/dev/null | grep '^State:' | cut -f2)
  echo "PID $pid: $name ($state)"
done