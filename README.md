# DLL Exports Extraction BOF

## What is this?
- This is a `Cobalt Strike` `BOF` file, meant to use two *or* three arguments (path to `DLL`, and/or a third argument `[all | fancy]`)
- If a third argument is supplied:
	- `all` extracts the values, and creates a string representation of a valid `.DEF` file for the provided `DLL`
	- `fancy` uses the work of [@anthemtotheego)](https://twitter.com/anthemtotheego) to create an `NTFS transaction` to provide a memory-residing copy of the corresponding data, which is then synchronized to your `Cobalt Strike` downloads view.


## What problem are you trying to solve?
1.  During recent conversations with colleagues in regard to `DLL`-based attacks; sideloading, proxying, insert-vector-here, it came to my attention that there are certain instances in which having the exact path to the *true* `DLL` to offload requests was necessary.
2.  I wanted to support both `32-bit` AND `64-bit` executable images.
3.  I wanted the `Base` to be represented properly, as *not all* ordinal base values begin at `1`.   I wanted the values to be *accurate*.
4.  I wanted an operator to understand how many functions in total are exported from a given executable, so they can make a better determination of whether to download a copy, send the output of this application to the `Beacon` console, or download an "in memory" variant of the contents.

## How do I build this?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory

## How do I use this?
- From a given `Beacon`:
![](https://i.ibb.co/wJxNcQ7/image.png)
##
## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk".
- You may attempt to incur a privileged action without sufficient requisite permissions.  I can't keep you from burning your hand.
- There are absolutely bugs in this code; these may or may not come down in the future.  I wrote this as a PoC.  [JohnLaTwC](https://github.com/JohnLaTwC) is my hero.
##
## What does the output look like?
#### Standard (Number-total only output):
![](https://i.ibb.co/sKR4mh7/image.png)

#### Verbose (***All*** data sent to beacon console):
![](https://i.ibb.co/mRRdRwN/image.png)

#### Transactional NTFS Download of File:
![](https://i.ibb.co/mqX6rCM/image.png)
![](https://i.ibb.co/5WzMHH0/image.png)
