#!/usr/bin/env php
<?php

$FILENAME = "fs_test1.dat";
$FILENAME_DOT_FIRST = ".fs_test2.dat";
$RANGE_MIN = 0;
$RANGE_MAX = 65536;
//$DEBUG = true;

function test($f) {
	global $FILENAME;

	$contents = @file_get_contents($f);	

	if (empty($contents)) {
		return false;
	} else {
		if (strpos($contents, "fuzz") === false) {
			die("Did not actually get file content!");
		}

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
	print("    ");

	for ($i = 0; $i < func_num_args(); $i++) {
		if ($i > 0) {
			print(", ");
		}

		$c = func_get_arg($i);

		print("0x" . dechex($c));

		if ($c >= 32) {
			print(" '" . utf8($c) . "'");
		}	
	}

	print("\n");
}

function print_platform_info() {
	print("Current PHP version: ");
	if (defined('PHP_VERSION_ID')) {
		print(PHP_VERSION);
	} else {
		print(phpversion());
	}

	print("\n\n");

	print("Operating system: " . php_uname() . "\n\n");

	if (defined('PHP_MAXPATHLEN')) {
		print("PHP_MAXPATHLEN: " . PHP_MAXPATHLEN . "\n\n");
	}

	print("Extensions: ");
	
	foreach (get_loaded_extensions() as $i => $ext) {
    	print($ext);
    	$version = phpversion($ext);
    	if (!empty($version)) {
    		print(" ($version) ");
    	}
	}

	print("\n");

	print("\n");
}

function pad_filename($FILENAME, $len) {
	$f = "./";
	
	while($len--) {
		$f = $f . "x";
	}

	$f = $f . "/../" . $FILENAME;

	return $f;
}

function test_append_string($FILENAME, $append) {
	global $DEBUG;
	
	print("Testing " . $append . " at the end of filename:\n");

	$f = $FILENAME . $append;

	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print("    yes\n");
	} else {
		print("    no\n");
	}
	
	print("\n");
}


// -- Main ---

print_platform_info();


// First check that we can actually open the test file.
if (!test($FILENAME)) {
	die("Could not open test file: $FILENAME\n");
}

// First check that we can actually open the test file.
if (!test($FILENAME_DOT_FIRST)) {
	die("Could not open test file: $FILENAME_DOT_FIRST\n");
}

// --------------------

print("Ignores dot at the beginning of file name:\n");

$f = substr($FILENAME_DOT_FIRST, 1);

if (isset($DEBUG)) {
	print("Try: $f\n");
}

if (test($f)) {
	print("    yes\n");
} else {
	print("    no\n");
}

print("\n");

// --------------------

print("Max path length (terminating NUL excluded):\n");

$len = 1;

for (;;) {
	$f = getcwd() . "/" . pad_filename($FILENAME, $len);

	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (!test($f)) {
		$MY_MAXPATHLEN = strlen($f);
		print("    " . $MY_MAXPATHLEN . "\n");
		break;
	}

	$len++;
}

print("\n");

// Determine if the characters after maximum length are ignored.

$f = getcwd() . "/" . pad_filename($FILENAME, $len - 1);
if (!test($f)) {
	die("Unexpected failure.\n");
}

$f = $f . "x";

if (isset($DEBUG)) {
	print("Try: $f\n");
}

if (test($f)) {
	print("Adding content past MAXPATHLEN works (len " . strlen($f) . ").\n");
} else {
	print("Adding content past MAXPATHLEN does not work (len " . strlen($f) . ").\n");
}

print("\n");

// --------------------

print("One character ignored when appended to a filename:\n");

$count = 0;

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = $FILENAME . utf8($c);

	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Two characters ignored when appended to a filename:\n");

$count = 0;

for ($c1 = $RANGE_MIN; $c1 < 256; $c1++) {
for ($c2 = $RANGE_MIN; $c2 < 256; $c2++) {
	$f = $FILENAME . utf8($c1) . utf8($c2);

	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c1, $c2);
		$count++;
	}
}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

test_append_string($FILENAME, "./");
test_append_string($FILENAME, "/.");
test_append_string($FILENAME, ".\\");
test_append_string($FILENAME, "\\.");
test_append_string($FILENAME, ".....");

// --------------------

print("Ignored when prepended to a filename:\n");

$count = 0;

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = utf8($c) . $FILENAME;

	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Ignored inside a filename:\n");

$count = 0;

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = substr($FILENAME, 0, 5) . utf8($c) . substr($FILENAME, 5);
	
	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Filename terminators:\n");

$count = 0;

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = $FILENAME . utf8($c) . ".some.random.stuff";
	
	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Single character wildcards:\n");

$count = 0;

$MY_FILENAME = substr($FILENAME, 0, strlen($FILENAME) - 1);
$last_char = substr($FILENAME, strlen($FILENAME) - 1, strlen($FILENAME));

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = $MY_FILENAME . utf8($c);
	
	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		if (strtolower($f) != strtolower($FILENAME)) {
			print_char($c);
			$count++;
		}
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Multi-character wildcards:\n");

$count = 0;

$MY_FILENAME = substr($FILENAME, 0, strlen($FILENAME) - 3);

for ($c = $RANGE_MIN; $c < $RANGE_MAX; $c++) {
	$f = $MY_FILENAME . utf8($c);
	
	if (isset($DEBUG)) {
		print("Try: $f\n");
	}

	if (test($f)) {
		print_char($c);
		$count++;
	}
}

if ($count == 0) {
	print("    none\n");
}

print("\n");

// --------------------

print("Double-quote works as a dot:\n");

$pos = strpos($FILENAME, ".");
if ($pos === false) {
	die("Test filename does not contain a dot: $FILENAME\n");
}

$f = substr($FILENAME, 0, $pos) . '"' . substr($FILENAME, $pos + 1, strlen($FILENAME));

if (isset($DEBUG)) {
	print("Try: $f\n");
}

if (test($f)) {
	print("    yes\n");
} else {
	print("    no\n");
}

print("\n");

?>