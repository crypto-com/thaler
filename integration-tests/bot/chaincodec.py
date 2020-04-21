import os
import scalecodec
import scalecodec.type_registry

path = os.path.dirname(__file__)

scalecodec.base.RuntimeConfiguration().update_type_registry(
    scalecodec.type_registry.load_type_registry_file(
        os.path.join(path, 'type_registry.json')
    )
)


def decode(name, bs):
    'decode SCALE binary'
    if not isinstance(bs, scalecodec.ScaleBytes):
        bs = scalecodec.ScaleBytes(bs)
    obj = scalecodec.ScaleDecoder.get_decoder_class(name, bs)
    return obj.decode()


if __name__ == '__main__':
    import fire
    fire.Fire(decode)
