from pyjon.utils import base_converter
import unittest
from nose.tools import raises

class TestConversion(unittest.TestCase):
    """test the base_converter module
    """
    def tearDown(self):
        pass

    def setUp(self):
        pass

    def test_n_to_m(self):
        """test base n to base m conversion
        """
        import uuid

        index = 0
        while index < 1000:
            u = uuid.uuid4().get_hex()
            su = base_converter.n_to_m(u, 16, 36)

            i = int(u, 16)
            bi = int(su, 36)

            assert i == bi, 'Conversion gave the representation in base 36 of %d instead of %d' % (bi, i)

            index += 1

    def test_decimal_to_n_zero(self):
        """test decimal to base n conversion of 0
        """
        zero = base_converter.decimal_to_n(0, 2)
        assert zero == "0"

    @raises(ValueError)
    def test_decimal_to_n_invalid_base(self):
        """test decimal to invalid base conversion
        """
        base_converter.decimal_to_n(25, 45)

    @raises(ValueError)
    def test_n_to_m_invalid_base_from(self):
        """test invalid base to base m conversion
        """
        base_converter.n_to_m("25", 45, 2)

    @raises(ValueError)
    def test_n_to_m_invalid_base_to(self):
        """test base n to invalid base conversion
        """
        base_converter.n_to_m("25", 8, 45)

# vim: expandtab tabstop=4 shiftwidth=4:
