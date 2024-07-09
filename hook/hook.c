
#include "hook.h"
#include "replace_aes.h"

#if defined __linux__
    #include <dlfcn.h>
#elif defined _WIN32
    #include <windows.h>
	#define dlsym GetProcAddress 
#endif

pfn_replace_fnc _replace_fnc = NULL;

pfn_aes_new             _orig_aes_new            = NULL; 
pfn_aes_free            _orig_aes_free           = NULL; 
pfn_aes_init            _orig_aes_init           = NULL; 
pfn_aes_block_size      _orig_aes_block_size     = NULL; 
pfn_aes_ksize_min       _orig_aes_ksize_min      = NULL; 
pfn_aes_ksize_max       _orig_aes_ksize_max      = NULL; 
pfn_aes_ksize_multiple  _orig_aes_ksize_multiple = NULL; 
pfn_aes_set_ekey        _orig_aes_set_ekey       = NULL; 
pfn_aes_set_dkey        _orig_aes_set_dkey       = NULL; 
pfn_aes_enc_block       _orig_aes_enc_block      = NULL; 
pfn_aes_dec_block       _orig_aes_dec_block      = NULL; 

zmerror hook_start(void* modue){
    if (!modue) 
        { return ZMCRYPTO_ERR_NULL_PTR; }

    _replace_fnc = (pfn_replace_fnc)dlsym(modue, "zm_replace_fnc");
    if (!_replace_fnc) 
        { return ZMCRYPTO_ERR_NULL_PTR; }

    _orig_aes_new            = (void*)_replace_fnc("zm_aes_new", hook_aes_new );
    _orig_aes_free           = (void*)_replace_fnc("zm_aes_free", hook_aes_free );    
    _orig_aes_init           = (void*)_replace_fnc("zm_aes_init", hook_aes_init );
    _orig_aes_block_size     = (void*)_replace_fnc("zm_aes_block_size", hook_aes_block_size );
    _orig_aes_ksize_min      = (void*)_replace_fnc("zm_aes_ksize_min", hook_aes_ksize_min );
    _orig_aes_ksize_max      = (void*)_replace_fnc("zm_aes_ksize_max", hook_aes_ksize_max );    
    _orig_aes_ksize_multiple = (void*)_replace_fnc("zm_aes_ksize_multiple", hook_aes_ksize_multiple );
    _orig_aes_set_ekey       = (void*)_replace_fnc("zm_aes_set_ekey", hook_aes_set_ekey);
    _orig_aes_set_dkey       = (void*)_replace_fnc("zm_aes_set_dkey", hook_aes_set_dkey);
    _orig_aes_enc_block      = (void*)_replace_fnc("zm_aes_enc_block", hook_aes_enc_block );
    _orig_aes_dec_block      = (void*)_replace_fnc("zm_aes_dec_block", hook_aes_dec_block );

    if (
        _orig_aes_new            == NULL || 
        _orig_aes_free           == NULL || 
        _orig_aes_init           == NULL || 
        _orig_aes_block_size     == NULL || 
        _orig_aes_ksize_min      == NULL || 
        _orig_aes_ksize_max      == NULL || 
        _orig_aes_ksize_multiple == NULL || 
        _orig_aes_set_ekey       == NULL || 
        _orig_aes_set_dkey       == NULL || 
        _orig_aes_enc_block      == NULL || 
        _orig_aes_dec_block      == NULL 
    )
    {
        return ZMCRYPTO_ERR_NULL_PTR;
    }

    return ZMCRYPTO_ERR_SUCCESSED;
}

zmerror hook_finish(){

    if (
        _orig_aes_new            == NULL || 
        _orig_aes_free           == NULL || 
        _orig_aes_init           == NULL || 
        _orig_aes_block_size     == NULL || 
        _orig_aes_ksize_min      == NULL || 
        _orig_aes_ksize_max      == NULL || 
        _orig_aes_ksize_multiple == NULL || 
        _orig_aes_set_ekey       == NULL || 
        _orig_aes_set_dkey       == NULL || 
        _orig_aes_enc_block      == NULL || 
        _orig_aes_dec_block      == NULL ||
        _replace_fnc             == NULL 
    )
    {
        return ZMCRYPTO_ERR_NULL_PTR;
    }

    (void)_replace_fnc("zm_aes_new",_orig_aes_new );
    (void)_replace_fnc("zm_aes_free", _orig_aes_free );
    (void)_replace_fnc("zm_aes_init", _orig_aes_init );
    (void)_replace_fnc("zm_aes_block_size", _orig_aes_block_size );
    (void)_replace_fnc("zm_aes_ksize_min", _orig_aes_ksize_min );
    (void)_replace_fnc("zm_aes_ksize_max", _orig_aes_ksize_max);
    (void)_replace_fnc("zm_aes_ksize_multiple", _orig_aes_ksize_multiple);
    (void)_replace_fnc("zm_aes_set_ekey", _orig_aes_set_ekey);
    (void)_replace_fnc("zm_aes_set_dkey", _orig_aes_set_dkey);
    (void)_replace_fnc("zm_aes_enc_block", _orig_aes_enc_block );
    (void)_replace_fnc("zm_aes_dec_block", _orig_aes_dec_block );

	_orig_aes_new = NULL;
	_orig_aes_free = NULL;
	_orig_aes_init = NULL;
	_orig_aes_block_size = NULL;
	_orig_aes_ksize_min = NULL;
	_orig_aes_ksize_max = NULL;
	_orig_aes_ksize_multiple = NULL;
	_orig_aes_set_ekey = NULL;
	_orig_aes_set_dkey = NULL;
	_orig_aes_enc_block = NULL;
	_orig_aes_dec_block = NULL;

    return ZMCRYPTO_ERR_SUCCESSED;
}
