#!/usr/bin/env php
<?php

$FILENAME = "test_fs_evasion.php";

function test($f) {
	$contents = @file_get_contents($f);	

	if (empty($contents)) {
		return false;
	} else {
		return true;
	}
}

// The following two functions retrieved from Stack Overflow
// http://stackoverflow.com/questions/1805802/php-convert-unicode-codepoint-to-utf-8

function utf8($num)
{
    if($num<=0x7F)       return chr($num);
    if($num<=0x7FF)      return chr(($num>>6)+192).chr(($num&63)+128);
    if($num<=0xFFFF)     return chr(($num>>12)+224).chr((($num>>6)&63)+128).chr(($num&63)+128);
    if($num<=0x1FFFFF)   return chr(($num>>18)+240).chr((($num>>12)&63)+128).chr((($num>>6)&63)+128).chr(($num&63)+128);
    return '';
}

function uniord($c)
{
    $ord0 = ord($c{0}); if ($ord0>=0   && $ord0<=127) return $ord0;
    $ord1 = ord($c{1}); if ($ord0>=192 && $ord0<=223) return ($ord0-192)*64 + ($ord1-128);
    $ord2 = ord($c{2}); if ($ord0>=224 && $ord0<=239) return ($ord0-224)*4096 + ($ord1-128)*64 + ($ord2-128);
    $ord3 = ord($c{3}); if ($ord0>=240 && $ord0<=247) return ($ord0-240)*262144 + ($ord1-128)*4096 + ($ord2-128)*64 + ($ord3-128);
    return false;
}

function print_char($c) {
	print("    0x" . dechex($c) . "\n");
}

// First check that we can actually open the test file.
if (!test($FILENAME)) {
	die("Could not open test file: $FILENAME\n");
}

// --------------------

print("Ignored when appended to a filename:\n");

$count = 0;

for ($c = 0; $c < 65536; $c++) {
	$f = $FILENAME . utf8($c);
	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none");
}

print("\n");

// --------------------

print("Ignored when prepended to a filename:\n");

$count = 0;

for ($c = 0; $c < 65536; $c++) {
	$f = utf8($c) . $FILENAME;
	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none");
}

print("\n");

// --------------------

print("Ignored inside a filename:\n");

$count = 0;

for ($c = 0; $c < 65536; $c++) {
	$f = substr($FILENAME, 0, 5) . utf8($c) . substr($FILENAME, 5);
	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none");
}

print("\n");

// --------------------

print("Filename terminators:\n");

$count = 0;

for ($c = 0; $c < 65536; $c++) {
	$f = $FILENAME . utf8($c) . ".some.random.stuff";
	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none");
}

print("\n");

?>