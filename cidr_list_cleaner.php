<?php
/**
 * CIDR List Cleaner
 *
 * CIDR List Cleaner cleans up lengthy lists of CIDRs, e.g., from an ASN lookup.
 * IPv4 & IPv6 supported.  List may contain IPs as well.  No embedded spaces allowed.
 *
 * ASN lists usually have massive amounts of duplication & overlap, and
 * frequently display large ip ranges as hundreds of smaller consecutive
 * ranges.  This utility cleans up duplication & overlap, and combines
 * ranges where possible.  The result can be a 98-99% reduction in list size.
 *
 * Input file must ONLY contain a list of CIDRs & IPs, one per line, in text.
 * The input file must be specified in the user configuration section below.
 *
 * To support ipv6 (128-bit unsigned ints), it works solely on the raw binary data.
 * No external libraries are required.
 *
 * Copyright 2025-2026 Shawn Bulen
 *
 * CIDR List Cleaner is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CIDR List Cleaner is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CIDR List Cleaner.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

// User configuration - just needs input & output files
// Optional command, e.g., to prepend 'Deny from' in the output file
$in_file = __DIR__ . '/asn_list_input.txt';
$out_file = __DIR__ . '/asn_list_output.txt';
$prefix_command = 'Require not ip';
// End of user configuration - no need to edit below this line

// Start of main program
if (stripos(PHP_SAPI, 'cli') === false)
	define('MY_EOL', '<br>');
else
	define('MY_EOL', PHP_EOL);

echo 'CIDR List Cleaner input: ' . $in_file . MY_EOL;
if (!file_exists($in_file))
	exit('******** Invalid input file ********');

$cidr_list = new CIDR_list($in_file, $prefix_command);
$cidr_list->write($out_file);

echo 'CIDR List Cleaner output: ' . $out_file . MY_EOL;
// End of main program

// Classes used
class CIDR
{
	/*
	 * Properties
	 */
	public $prefix = '0.0.0.0';
	public $prefix_len = 32;
	public $prefix_dec = 0;
	public $prefix_packed = '';
	public $prefix_hex = '';

	public $min_ip = '0.0.0.0';
	public $min_dec = 0;
	public $min_packed = '';
	public $min_hex = '';

	public $max_ip = '0.0.0.0';
	public $max_dec = 0;
	public $max_packed = '';
	public $max_hex = '';

	public $ipv6 = false;
	public $valid = false;
	public $int_size = 32;

	/**
	 * Constructor
	 *
	 * Builds a CIDR object.  Input is a string, containing a CIDR or an IP address.
	 * No spaces within CIDR/IP string.  Will build valid objects for ipv4 or ipv6 CIDRs.
	 *
	 * @param string $cidr
	 * @return void
	 */
	function __construct($cidr = '0.0.0.0/32')
	{
		// [0] = whole, [1] = prefix, [2] = prefix length
		$matches = array();
		preg_match('~^\s*([^\/\s]{2,45})(\/.*)?~', $cidr, $matches);

		// No hit at all...
		if (empty($matches))
		{
		    echo '*** Invalid CIDR skipped: ' . $cidr . MY_EOL;
		    return;
		}

		// Prefix must be a valid IP...
		if (filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
		{
			$this->prefix = $matches[1];
			$this->ipv6 = false;
			$this->int_size = 32;
		}
		elseif (filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
		{
			$this->prefix = $matches[1];
			$this->ipv6 = true;
			$this->int_size = 128;
		}
		else
		{
		    echo '*** Invalid CIDR prefix skipped: ' . $cidr . MY_EOL;
			return;
		}

		// If provided, length must be valid per ipv4/ipv6.
		if (isset($matches[2]))
		{
			$pfx_match = array();
			preg_match('~\/(\d{1,3})\b~', $matches[2], $pfx_match);
			if (!empty($pfx_match) && (((int) $pfx_match[1]) >= 0) && (((int) $pfx_match[1]) <= $this->int_size))
			{
				$this->prefix_len =  (int) $pfx_match[1];
			}
			else
			{
				echo '*** Invalid CIDR length skipped: ' . $cidr . MY_EOL;
				return;
			}
		}
		else
		{
			// if Length not provided, it is an IP, so use int_size...
			$this->prefix_len = $this->int_size;
		}

		// OK, you've run the gauntlet...
		$this->valid = true;

		$this->prefix_packed = inet_pton($this->prefix);
		$this->prefix_hex = bin2hex($this->prefix_packed);
		$this->prefix_dec = Packed::packeddec($this->prefix_packed, 2, 10);

		// Calc min & max
		$ip_mask = Packed::rmask($this->int_size - $this->prefix_len, $this->int_size);
		$this->max_packed = $this->prefix_packed | $ip_mask;
		$this->max_ip = inet_ntop($this->max_packed);
		$this->max_hex = bin2hex($this->max_packed);
		$this->max_dec = Packed::packeddec($this->max_packed);

		$ip_mask = ~$ip_mask;
		$this->min_packed = $this->prefix_packed & $ip_mask;
		$this->min_ip = inet_ntop($this->min_packed);
		$this->min_hex = bin2hex($this->min_packed);
		$this->min_dec = Packed::packeddec($this->min_packed);
	}

	public function to_text()
	{
	    return $this->prefix . '/' . $this->prefix_len;
	}

	// Quick check to see if an IP (passed in packed format) is within this CIDR
	public function contains($ip_packed)
	{
		return (($ip_packed >= $this->min_packed) && ($ip_packed <= $this->max_packed));
	}

	/**
	 * Calculate a CIDR (or set of CIDRs) for an IP range provided in packed format.
	 * Output is an array of CIDRs in string format (e.g., "77.88.0.0/16").  It must be an array
	 * because it may take more than one CIDR to describe the requested IP range.
	 *
	 * Algorithm informed by: https://blog.ip2location.com/knowledge-base/how-to-convert-ip-address-range-into-cidr/
	 * Great article, short & to the point, with examples.
	 */
	static function build($min, $max, $int_size)
	{
		// Need to whittle away at these...  Break one big range down to a number of
		// smaller ranges that can each be expressed in CIDR format.
		$cidrs = array();

		// Start at the min end of the range, build the biggest CIDR you can that's still smaller
		// than the WHOLE range, that starts with the curr min value, add to $cidrs[], increment min
		// to account for covering that entry, & repeat.
		while($max >= $min)
		{
			// $prefix = current subrange prefix; find the biggest prefix that works via
			// stepping thru left-justified masks.  ((Int_size - 0) bits on the right of $min...)
			$prefix = $int_size;
			while ($prefix > 0)
			{
				$mask = Packed::lmask($prefix - 1, $int_size);
				$mask_base = $min & $mask;
				if($mask_base != $min)
					break;
				$prefix--;
			}

			// $smallest_prefix = biggest power of 2 that stays within the remaining range... small prefix = big #...
			//  (= Count up to first 1 bit in binary representation of $diff...)
			// $diff = $max - $min + 1 = number of IPs in range
			$diff = Packed::subtract($max, $min);
			$diff = Packed::inc($diff);
			$smallest_prefix = 0;
			while ($smallest_prefix <= $int_size)
			{
				$mask = Packed::lmask($smallest_prefix, $int_size);
				$mask_base = $diff & $mask;
				if(!Packed::is_zero($mask_base))
					break;
				$smallest_prefix++;
			}
			// This can happen when testing extremes & need more bits than you got...
			if ($smallest_prefix > $int_size)
				$smallest_prefix = 0;
			// Prevent overshoot...
			if($prefix < $smallest_prefix)
				$prefix = $smallest_prefix;

			$cidrs[] = inet_ntop($min) . '/' . $prefix;

			$pow2 = Packed::pow2($int_size - $prefix, $int_size);
			$min = Packed::add($min, $pow2);

			// This can happen when testing extremes & need more bits than you got...
			// Face it, you're done already...
			if (($prefix === 0) || (Packed::is_zero($min)))
				break;
		}
		return $cidrs;
	}
}

/**
 * A bunch of static functions for dealing with packed values, such as output from inet_pton().
 */
class Packed
{
	// Generates packed mask based on specified length...
	// With $size number of rightmost bits set...
	static function rmask($size, $int_size)
	{
		$bytes = (int) $int_size / 8;
		$mask = '';
		for ($i = $bytes; $i > 0; $i--)
		{
			if ($size >= ($i * 8))
				$setbits = 8;
			elseif($size <= (($i - 1) * 8))
				$setbits = 0;
			else
				$setbits = ($size - (($i - 1) * 8));

			$mask .= chr((2 ** $setbits) - 1);
		}
		return $mask;
	}

	// Generates packed mask based on specified length...
	// With $size number of leftmost bits set...
	static function lmask($size, $int_size)
	{
		// Heck, leverage the other guy...
		$mask = Packed::rmask($int_size - $size, $int_size);
		$mask = ~$mask;
		return $mask;
	}

	// Translates packed to decimal.
	// Works for any size, but, for ipv6, may end up returning a float, not an int.
	// ***I.e., can't do math with this output...***
	static function packeddec($packed)
	{
		$len = strlen($packed);
		$dec = 0;
		for ($i = $len - 1; $i >= 0; $i--)
			$dec += ord(substr($packed, $i, 1))*(256**(($len - 1) - $i));
		return $dec;
	}

	// Translates int to packed.
	// ***Only works for values small enough to be represented by an int.***
	static function decpacked($dec, $int_size)
	{
		$fmt = ($int_size === 32) ? 'N' : 'J';
		$packed = pack($fmt, $dec);
		return $packed;
	}

	// Add two packed values.
	static function add($value1, $value2)
	{
		$bytes = strlen($value1);
		$new = '';
		$co = 0;
		for ($i = $bytes - 1; $i >= 0; $i--)
		{
			$temp = ord(substr($value1, $i, 1)) + ord(substr($value2, $i, 1)) + $co;
			if ($temp > 255)
			{
				$co = 1;
				$temp = $temp - 256;
			}
			else
			{
				$co = 0;
			}
			$new = chr($temp) . $new;
		}
		return $new;
	}

	// Subtract two packed values.
	static function subtract($value1, $value2)
	{
		$bytes = strlen($value1);
		$new = '';
		$bo = 0;
		for ($i = $bytes - 1; $i >= 0; $i--)
		{
			$temp = ord(substr($value1, $i, 1)) - ord(substr($value2, $i, 1)) - $bo;
			if ($temp < 0)
			{
				$bo = 1;
				$temp = $temp + 256;
			}
			else
			{
				$bo = 0;
			}
			$new = chr($temp) . $new;
		}
		return $new;
	}

	// Check if zero.
	static function is_zero($packed)
	{
		$bytes = strlen($packed);
		$zero = true;
		for ($i = $bytes - 1; $i >= 0; $i--)
		{
			if (ord(substr($packed, $i, 1)) !== 0)
			{
				$zero = false;
				break;
			}
		}
		return $zero;
	}

	// Add one.
	static function inc($packed)
	{
		$bytes = strlen($packed);
		$new = '';
		$co = 0;
		for ($i = $bytes - 1; $i >= 0; $i--)
		{
			$temp = ord(substr($packed, $i, 1)) + $co;
			if ($i === ($bytes - 1))
				$temp++;
			if ($temp > 255)
			{
				$co = 1;
				$temp = 0;
			}
			else
			{
				$co = 0;
			}
			$new = chr($temp) . $new;
		}
		return $new;
	}

	// Create a packed value for the given power of 2...
	static function pow2($value, $int_size)
	{
		$bytes = (int) ($int_size / 8);
		$value = (int) $value;
		$new = '';
		for ($i = $bytes; $i > 0; $i--)
		{
			if (($value < 8) && ($value >= 0))
				$temp = 2 ** $value;
			else
				$temp = 0;
			$new = chr($temp) . $new;
			$value = (int) ($value - 8);
		}
		return $new;
	}
}

class CIDR_list
{
	/*
	 * Properties
	 */
	public $cidrs_ipv4 = array();
	public $cidrs_ipv6 = array();
	public $command = '';

	/**
	 * Constructor
	 *
	 * Builds a CIDR_list object given a raw input file.
	 * Input file must ONLY contain a list of CIDRs, one per line.
	 *
	 * @param string $file = filename of input file
	 * @param string $command = allows you to prepend a command to lines of output produced, e.g., 'Deny from'
	 * @return void
	 */
	function __construct($file, $command = '')
	{
		// Save off command, & ensure it ends in a space
		if (!empty($command) && is_string($command))
			$this->command = trim($command) . ' ';

		$fp = fopen($file, 'r');

		// Load the file
		$buffer = fgets($fp);
		while ($buffer !== false)
		{
			$buffer = trim($buffer);
			$temp_cidr = new CIDR($buffer);
			// Don't keep items that didn't convert OK (comments, etc...)
			if ($temp_cidr->valid)
			{
				// ipv6
				if ($temp_cidr->ipv6)
				{
					// Get rid of dupes & overlaps, with same starting min-value...
					if (key_exists($temp_cidr->min_packed, $this->cidrs_ipv6))
					{
						// If same starting value, keep the one with the lower prefix (wider range)...
						if ($this->cidrs_ipv6[$temp_cidr->min_packed]->prefix_len > $temp_cidr->prefix_len)
							$this->cidrs_ipv6[$temp_cidr->min_packed] = $temp_cidr;
					}
					else
						$this->cidrs_ipv6[$temp_cidr->min_packed] = $temp_cidr;
				}
				// ipv4
				else
				{
					// Get rid of dupes & overlaps, with same starting min-value...
					if (key_exists($temp_cidr->min_packed, $this->cidrs_ipv4))
					{
						// If same starting value, keep the one with the lower prefix (wider range)...
						if ($this->cidrs_ipv4[$temp_cidr->min_packed]->prefix_len > $temp_cidr->prefix_len)
							$this->cidrs_ipv4[$temp_cidr->min_packed] = $temp_cidr;
					}
					else
						$this->cidrs_ipv4[$temp_cidr->min_packed] = $temp_cidr;
				}
			}
			$buffer = fgets($fp);
		}
		fclose($fp);

		// Subsequent cleaning needs these sorted...
		ksort($this->cidrs_ipv4);
		ksort($this->cidrs_ipv6);

		// Loop thru & delete items that are already included in previous item...
		$this->remove_subsets($this->cidrs_ipv4);
		$this->remove_subsets($this->cidrs_ipv6);

		// Combine consecutive CIDRs...
		$this->cidrs_ipv4 = $this->combine_consecutive($this->cidrs_ipv4);
		$this->cidrs_ipv6 = $this->combine_consecutive($this->cidrs_ipv6);
	}

	// Remove subsets
	public function remove_subsets(&$cidrs)
	{
		$first_entry = true;
		foreach ($cidrs AS $entry)
		{
			if ((!$first_entry) && ($prev_cidr->contains($entry->min_packed) && $prev_cidr->contains($entry->max_packed)))
				unset($cidrs[$entry->min_packed]);
			else
			{
				$prev_cidr = $entry;
				$first_entry = false;
			}
		}
	}

	// Combine where possible
	public function combine_consecutive(&$cidrs)
	{
		// Note they don't always combine into one, sometimes 15 CIDRs combine into 3...
		$curr_range_start = '';
		$curr_range_end = '';
		$cleansed_cidrs = array();
		$first_entry = true;
		foreach ($cidrs AS $entry)
		{
			if ($first_entry)
			{
				$curr_range_start = $entry->min_packed;
				$curr_range_end = $entry->max_packed;
				$int_size = $entry->int_size;
				$first_entry = false;
			}
			// These are consecutive, combine & keep going, not done yet...
			elseif (Packed::inc($prev_cidr->max_packed) === $entry->min_packed)
			{
				$curr_range_end = $entry->max_packed;
			}
			// These are not consecutive, spit out prev CIDR & start a new range to evaluate...
			else
			{
				foreach (CIDR::build($curr_range_start, $curr_range_end, $int_size) AS $temp)
					$cleansed_cidrs[] = new CIDR($temp);
				$curr_range_start = $entry->min_packed;
				$curr_range_end = $entry->max_packed;
			}
			$prev_cidr = $entry;
		}
		// Wrapup last range...
		if (!$first_entry)
			foreach (CIDR::build($curr_range_start, $curr_range_end, $int_size) AS $temp)
				$cleansed_cidrs[] = new CIDR($temp);

		// Update obj list of CIDRs
		return $cleansed_cidrs;
	}

	// Write the cleansed list to a text file.
	public function write($file)
	{
		$fp = fopen($file, 'w');
		foreach($this->cidrs_ipv4 AS $entry)
			fputs($fp, $this->command . $entry->to_text() . "\n");
		foreach($this->cidrs_ipv6 AS $entry)
			fputs($fp, $this->command . $entry->to_text() . "\n");
		fclose($fp);
	}
}
